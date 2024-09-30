import nmap
import numpy as np

from sklearn.ensemble import RandomForestClassifier

# Function to scan the network using Nmap
def network_scan(network_range='192.168.1.0/24'):
    # Initialize the port scanner
    nm = nmap.PortScanner()
    nm.scan(network_range, arguments='-sn')  # Ping scan
    
    devices = []
    
    # Iterate through all hosts found
    for host in nm.all_hosts():
        state = nm[host].state()
        mac = nm[host]['addresses'].get('mac', 'N/A')
        devices.append({
            'ip': host,
            'mac': mac,
            'state': state,
        })
    
    return devices

# Function to detect problems in the network
def detect_problems(devices):
    problems = []
    
    for device in devices:
        # Check if the device is down
        if device['state'] != 'up':
            problems.append({
                'device': device,
                'problem': 'Device is down',
                'solution': 'Check if the device is powered on and connected to the network properly.'
            })
    
    return problems

# Simple AI model for detecting common problems based on past data
def ml_predict(problem_data):
    # Example training data (1 = Device is down, 0 = No issue)
    X_train = np.array([
        [1, 0, 0],  # Problem 1: Device is down
        [0, 1, 0],  # Problem 2: Port issue
        [0, 0, 1],  # Problem 3: Security vulnerability
    ])
    
    # Labels: 0 = Device down, 1 = Port issue, 2 = Security vulnerability
    y_train = np.array([0, 1, 2])
    
    # Train a simple classifier
    model = RandomForestClassifier()
    model.fit(X_train, y_train)
    
    # Predict based on the new problem
    prediction = model.predict(problem_data)
    
    # Map prediction to problem and solution
    problem_map = {
        0: ('Device is down', 'Check power and network connection.'),
        1: ('Port issue', 'Check firewall and open necessary ports.'),
        2: ('Security vulnerability', 'Apply necessary security patches and check firewall settings.')
    }
    
    return problem_map[prediction[0]]

if __name__ == '__main__':
    # Scan the network and retrieve devices
    devices = network_scan()
    print("Devices found on the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, State: {device['state']}")
    
    # Detect problems with the devices
    problems = detect_problems(devices)
    print("\nProblems detected:")
    for problem in problems:
        print(f"Device IP: {problem['device']['ip']}, Problem: {problem['problem']}")
        print(f"Suggested solution: {problem['solution']}")
    
    # Run a mock prediction for a new problem (e.g., a device is down)
    print("\nUsing AI model to predict potential issues and solutions...")
    problem_data = np.array([[1, 0, 0]])  # Example input for the ML model (device down)
    problem, solution = ml_predict(problem_data)
    print(f"Predicted problem: {problem}")
    print(f"Suggested solution: {solution}")
