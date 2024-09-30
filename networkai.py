import nmap
import json
import joblib  # For loading the trained model

# Load the trained model (you need to train this model separately)
model = joblib.load('network_model.pkl')

def analyze_results(scan_results):
    # Analyze scan results and predict issues
    features = extract_features(scan_results)  # Function to extract features for the model
    prediction = model.predict([features])  # Make a prediction
    return prediction

def extract_features(scan_results):
    # Extract relevant features for the model (this is just an example)
    features = []
    open_ports = sum(1 for host in scan_results.all_hosts() for proto in scan_results[host].all_protocols() for port in scan_results[host][proto])
    features.append(open_ports)
    # Add more features based on your model requirements
    return features

def scan_network(target):
    nm = nmap.PortScanner()

    try:
        print(f"Scanning {target}...")
        nm.scan(target, arguments='-A -sV -O -T4 -v')

        for host in nm.all_hosts():
            print(f'Host: {host} ({nm[host].hostname()})')
            print(f'State: {nm[host].state()}')
            print('Protocols:')
            
            # Output the scan results as a dictionary for analysis
            scan_results = nm[host]
            prediction = analyze_results(nm)

            print(f'Predicted Issues: {prediction[0]}')
            for proto in scan_results.all_protocols():
                print(f'  Protocol: {proto}')
                lport = scan_results[proto].keys()
                for port in sorted(lport):
                    state = scan_results[proto][port]['state']
                    service = scan_results[proto][port]['name']
                    version = scan_results[proto][port]['version']
                    print(f'    Port: {port}\tState: {state}\tService: {service}\tVersion: {version}')
            print()

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    target = input("Enter IP Range (e.g., 192.168.1.0/24): ")
    scan_network(target)

