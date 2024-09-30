import nmap
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import os

# Define constants
MODEL_FILE = 'network_model.pkl'
RESULTS_FILE = 'scan_results.json'
MAX_REQUESTS = 100  # Maximum number of requests before timing out

def save_results(scan_results):
    """Save scan results to a JSON file."""
    with open(RESULTS_FILE, 'w') as f:
        json.dump(scan_results, f)

def load_or_train_model():
    """Load a trained model or train a new one if not available."""
    if os.path.exists(MODEL_FILE):
        model = joblib.load(MODEL_FILE)
        print("Loaded existing model.")
    else:
        print("No model found. Training a new model...")
        
        # Create a dummy dataset for training
        dummy_data = {
            'open_ports': [1, 2, 5, 10],
            'service_count': [1, 2, 3, 4],
            'label': ['secure', 'vulnerable', 'vulnerable', 'needs attention']
        }
        df = pd.DataFrame(dummy_data)

        # Prepare the features and labels
        features = df[['open_ports', 'service_count']]
        labels = df['label']

        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

        # Train the model
        model = RandomForestClassifier()
        model.fit(X_train, y_train)

        # Save the model
        joblib.dump(model, MODEL_FILE)
        print("Model trained and saved.")

    return model

def analyze_results(scan_results, model):
    """Analyze scan results and predict issues."""
    features = extract_features(scan_results)
    prediction = model.predict([features])
    return prediction

def extract_features(scan_results):
    """Extract relevant features for the model."""
    open_ports = sum(1 for host in scan_results.all_hosts() for proto in scan_results[host].all_protocols() for port in scan_results[host][proto])
    service_count = sum(len(scan_results[host][proto]) for host in scan_results.all_hosts() for proto in scan_results[host].all_protocols())
    return [open_ports, service_count]

def scan_network(target):
    """Scan the specified target network and display results."""
    nm = nmap.PortScanner()

    try:
        print(f"Scanning {target} with detailed options...")

        # Detailed scan options for more comprehensive results
        nm.scan(target, arguments='-A -sV -O -p- -T4 -v --max-retries 0')

        scan_results = {}
        request_count = 0  # Counter for requests made

        for host in nm.all_hosts():
            if request_count >= MAX_REQUESTS:
                print(f"Reached maximum request limit of {MAX_REQUESTS}. Stopping scan.")
                break
            
            scan_results[host] = {
                'hostname': nm[host].hostname(),
                'state': nm[host].state(),
                'protocols': {}
            }

            for proto in nm[host].all_protocols():
                scan_results[host]['protocols'][proto] = {}
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    scan_results[host]['protocols'][proto][port] = {
                        'state': nm[host][proto][port]['state'],
                        'service': nm[host][proto][port]['name'],
                        'version': nm[host][proto][port]['version'],
                        'product': nm[host][proto][port].get('product', 'N/A'),  # Product name, if available
                        'extrainfo': nm[host][proto][port].get('extrainfo', 'N/A'),  # Extra info, if available
                        'cpe': nm[host][proto][port].get('cpe', 'N/A'),  # Common Platform Enumeration
                    }
                    request_count += 1  # Increment request count
                    if request_count >= MAX_REQUESTS:
                        print(f"Reached maximum request limit of {MAX_REQUESTS}. Stopping scan.")
                        break
            if request_count >= MAX_REQUESTS:
                break

        save_results(scan_results)

        # Analyze results with AI model
        prediction = analyze_results(nm, model)
        print(f'Predicted Issues: {prediction[0]}')

        # Display scan results
        for host, data in scan_results.items():
            print(f'Host: {host} ({data["hostname"]})')
            print(f'State: {data["state"]}')
            for proto, ports in data['protocols'].items():
                print(f'  Protocol: {proto}')
                for port, info in ports.items():
                    print(f'    Port: {port}\tState: {info["state"]}\tService: {info["service"]}\tVersion: {info["version"]}\tProduct: {info["product"]}\tExtra Info: {info["extrainfo"]}\tCPE: {info["cpe"]}')
            print()

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    model = load_or_train_model()
    target = input("Enter IP Range (e.g., 192.168.1.0/24): ")
    scan_network(target)
