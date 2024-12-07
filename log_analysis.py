import re
import csv
from collections import defaultdict


FAILED_LOGIN_THRESHOLD = 10


def count_requests_per_ip(log_file):
    ip_count = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip_address = match.group(1)
                ip_count[ip_address] += 1
    return ip_count

def most_accessed_endpoint(log_file):
    endpoint_count = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'"(?:GET|POST) (/[\w/-]*) ', line)
            if match:
                endpoint = match.group(1)
                endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count, key=endpoint_count.get)
    return most_accessed, endpoint_count[most_accessed]

def detect_suspicious_activity(log_file, threshold=FAILED_LOGIN_THRESHOLD):
    failed_login_count = defaultdict(int)
    suspicious_ips = []
    
    with open(log_file, 'r') as file:
        for line in file:
            if '401' in line or 'Invalid credentials' in line:
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip_address = match.group(1)
                    failed_login_count[ip_address] += 1

    for ip, count in failed_login_count.items():
        if count > threshold:
            suspicious_ips.append((ip, count))
    
    return suspicious_ips


def output_results(ip_counts, most_accessed, suspicious_ips):
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}          {count}")
    
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips:
            print(f"{ip}        {count}")
    else:
        print("\nNo suspicious activity detected.")


def save_results_to_csv(ip_counts, most_accessed, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, count in ip_counts.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})
        
        writer.writerow({'IP Address': 'Most Accessed Endpoint', 'Request Count': most_accessed[0]})
        writer.writerow({'IP Address': 'Access Count', 'Request Count': most_accessed[1]})
        
        writer.writerow({'IP Address': 'Suspicious Activity', 'Request Count': ''})
        for ip, count in suspicious_ips:
            writer.writerow({'IP Address': ip, 'Request Count': count})

def main():
    log_file = 'sample.log'
    ip_counts = count_requests_per_ip(log_file)
    most_accessed = most_accessed_endpoint(log_file)
    suspicious_ips = detect_suspicious_activity(log_file)
    output_results(ip_counts, most_accessed, suspicious_ips)
    save_results_to_csv(ip_counts, most_accessed, suspicious_ips)

if __name__ == '__main__':
    main()
