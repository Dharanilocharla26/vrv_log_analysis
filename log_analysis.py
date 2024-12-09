import csv
from collections import Counter

# Function to count requests per IP address
def count_requests_per_ip(log_file):
    ip_counts = Counter()
    try:
        with open(log_file, 'r') as file:
            for line in file:
                parts = line.split()
                if len(parts) > 0:
                    ip = parts[0]  # Extract IP address
                    ip_counts[ip] += 1
        return ip_counts
    except FileNotFoundError:
        print(f"Error: File {log_file} not found.")
        return Counter()
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        return Counter()

#This Function to find the most accessed endpoint
def most_accessed_endpoint(log_file):
    endpoint_counts = Counter()
    try:
        with open(log_file, 'r') as file:
            for line in file:
                parts = line.split('"')  
                if len(parts) > 1:
                    request = parts[1].split(' ')
                    if len(request) > 1:
                        endpoint = request[1]  # Extracting the endpoint
                        endpoint_counts[endpoint] += 1
        if endpoint_counts:
            return endpoint_counts.most_common(1)[0]  # Return most accessed endpoint
        else:
            return None  # No endpoints found
    except Exception as e:
        print(f"Error reading log file: {e}")
        return None

# Function to detect suspicious activity (failed login attempts)***
def detect_suspicious_activity(log_file):
    failed_attempts = Counter()
    try:
        with open(log_file, 'r') as file:
            for line in file:
                if "401" in line:  # HTTP status code for unauthorized
                    parts = line.split()
                    if len(parts) > 0:
                        ip = parts[0]  # Extract IP address
                        failed_attempts[ip] += 1
        return failed_attempts
    except Exception as e:
        print(f"An error occurred while detecting suspicious activity: {e}")
        return Counter()

# Function to write results to a CSV file
def write_to_csv(ip_counts, most_accessed, suspicious_activity):
    try:
        with open('log_analysis_results.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write requests per IP
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_counts.items():
                writer.writerow([ip, count])

            writer.writerow([]) 

            # Write most accessed endpoint
            writer.writerow(["Most Accessed Endpoint", "Access Count"])
            if most_accessed:
                writer.writerow(most_accessed)
            else:
                writer.writerow(["No endpoints found"])

            writer.writerow([]) 

            # Write suspicious activity
            writer.writerow(["Suspicious Activity (Failed Login Attempts)"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_activity.items():
                writer.writerow([ip, count])

        print("Results have been written to log_analysis_results.csv")
    except Exception as e:
        print(f"An error occurred while writing to CSV: {e}")

# Main function
def main():
    log_file = "sample.log" 

    # Analyze the log file
    ip_counts = count_requests_per_ip(log_file)
    most_accessed = most_accessed_endpoint(log_file)
    suspicious_activity = detect_suspicious_activity(log_file)

    # Printing the results
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip} - {count} requests")

    print("\nMost Accessed Endpoint:")
    if most_accessed:
        top_endpoint, endpoint_count = most_accessed
        print(f"{top_endpoint} (Accessed {endpoint_count} times)")
    else:
        print("No endpoints found in the log file.")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip} - {count} failed login attempts")

    # Write results to CSV
    write_to_csv(ip_counts, most_accessed, suspicious_activity)

# Entry point of the script
if __name__ == "__main__":
    main()
