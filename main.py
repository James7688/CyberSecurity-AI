import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import joblib
import subprocess
import socket
import time
import platform


# Load and preprocess the dataset
def load_and_preprocess_data(file_path):
    data = pd.read_csv(file_path)
    data.dropna(inplace=True)  # Remove rows with missing values
    return data


# Train the anomaly detection model
def train_model(features):
    model = IsolationForest(contamination=0.01)  # Set contamination based on expected outlier rate
    model.fit(features)
    return model


# Save the trained model
def save_model(model, filename):
    joblib.dump(model, filename)


# Load the trained model
def load_model(filename):
    return joblib.load(filename)


# Predict anomalies
def predict_anomalies(model, features):
    return model.predict(features)


# Plot the results and show the plot
def plot_results(data):
    plt.figure(figsize=(10, 6))
    colors = data['anomaly'].apply(lambda x: 'blue' if x == -1 else 'red')
    plt.scatter(data['feature1'], data['feature2'], c=colors, s=50, edgecolor='k', alpha=0.7)
    plt.xlabel('Feature 1')
    plt.ylabel('Feature 2')
    plt.title('Cybersecurity AI')
    plt.colorbar(label='Anomaly Score')
    plt.show()


# Determine the appropriate command for blocking IPs based on OS
def block_ip(ip_address):
    os_name = platform.system()
    try:
        if os_name == 'Linux' or os_name == 'Darwin':  # Darwin is for MacOS
            # Example command for Linux and MacOS
            result = subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                                    check=True, capture_output=True, text=True)
        elif os_name == 'Windows':
            # Example command for Windows (requires admin privileges)
            result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Block IP"',
                                     'dir=in', 'action=block', 'remoteip=' + ip_address],
                                    check=True, capture_output=True, text=True)
        else:
            print("Unsupported operating system")
            return
        print(f"Successfully blocked IP address: {ip_address}")
        print(f"Command output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP address {ip_address}: {e.stderr}")


# Automate fixes for your own computer with progress reporting
def automate_fixes(anomalies):
    print("Starting to fix anomalies...")
    for index, row in anomalies.iterrows():
        ip_address = row.get('ip_address', 'N/A')
        location = row.get('location', 'Unknown')
        print(f"Processing anomaly {index}: IP address: {ip_address}, Location: {location}")
        if ip_address != 'N/A':
            block_ip(ip_address)
        else:
            print(f"Anomaly at location: {location} with IP address: {ip_address} could not be fixed automatically.")
        time.sleep(1)  # Adding a delay to simulate progress and avoid flooding
    print("Finished fixing anomalies.")


# Main function
def main():
    # Paths to the data files
    train_file = 'network_traffic.csv'
    new_data_file = 'new_network_traffic.csv'
    model_file = 'anomaly_model.pkl'

    # Load and preprocess data
    data = load_and_preprocess_data(train_file)
    print("Loaded data from training file:")
    print(data.head())  # Print the first few rows to check the data

    features = data[['feature1', 'feature2', 'feature3']]

    # Train the model
    model = train_model(features)

    # Save the model
    save_model(model, model_file)

    # Load the model
    model = load_model(model_file)

    # Predict anomalies on the original data
    data['anomaly'] = predict_anomalies(model, features)

    # Count and print anomalies
    num_anomalies = (data['anomaly'] == -1).sum()
    print(f'Number of anomalies detected: {num_anomalies}')

    # Print anomaly locations
    anomalies = data[data['anomaly'] == -1]
    if not anomalies.empty:
        print("Anomalies detected at the following locations:")
        for index, row in anomalies.iterrows():
            ip_address = row.get('ip_address', 'N/A')
            location = row.get('location', 'Unknown')
            print(f"Anomaly {index}: IP address: {ip_address}, Location: {location}")

    # Plot results
    plot_results(data)

    # Automate fixes if anomalies are on your own computer
    if not anomalies.empty:
        local_ip = socket.gethostbyname(socket.gethostname())
        if any(anomalies['ip_address'] == local_ip):
            automate_fixes(anomalies)

    # Predict anomalies on new data
    new_data = load_and_preprocess_data(new_data_file)
    print("Loaded data from new data file:")
    print(new_data.head())  # Print the first few rows to check the data

    new_features = new_data[['feature1', 'feature2', 'feature3']]
    new_predictions = predict_anomalies(model, new_features)

    print(f'Anomalies in new data: {sum(new_predictions == -1)}')


if __name__ == '__main__':
    main()