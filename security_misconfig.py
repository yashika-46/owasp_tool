import requests
import nmap
import ssl
import socket
from http.cookies import SimpleCookie
import time
from urllib.parse import urlparse

# Ask user for input type
input_type = input("Do you want to scan a single URL or a file? (enter 'url' or 'file'): ").strip().lower()
output = input("Enter the output filename to save results (leave blank to skip saving): ").strip()

# Function: Check SSL certificate details
def check_ssl_info(hostname):
    result = "\n--- SSL/TLS Certificate Info ---\n"
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                result += f"TLS Version: {tls_version}\n"
                result += f"Issuer: {cert.get('issuer')}\n"
                result += f"Subject: {cert.get('subject')}\n"
                result += f"Valid From: {cert.get('notBefore')}\n"
                result += f"Valid Until: {cert.get('notAfter')}\n"
    except Exception as e:
        result += f"SSL info fetch error: {e}\n"
    return result

# Function: BurpSuite-style HTTP scan (Enhanced)
def def_burpsuite(target_url):
    result = f"\n========== Burp Suite Scan for {target_url} ==========\n"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; security_misconfig/1.0)'}
        start_time = time.time()
        response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
        response_time = time.time() - start_time

        result += f"\nHTTP Status Code: {response.status_code}\n"
        result += f"Response Time: {response_time:.2f} seconds\n"
        result += f"Final URL after redirects: {response.url}\n"

        result += "\n--- Response Headers ---\n"
        for k, v in response.headers.items():
            result += f"{k}: {v}\n"

        # Check Security Headers
        sec_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options', 'Content-Security-Policy']
        result += "\n--- Important Security Headers ---\n"
        for h in sec_headers:
            result += f"{h}: {response.headers.get(h, 'Not Set')}\n"

        # Check Cookies
        set_cookie_header = response.headers.get('Set-Cookie')
        result += "\n--- Cookies ---\n"
        if set_cookie_header:
            cookie = SimpleCookie()
            cookie.load(set_cookie_header)
            for key, morsel in cookie.items():
                result += f"Cookie: {key}\n"
                result += f" - Secure: {'Secure' in set_cookie_header}\n"
                result += f" - HttpOnly: {'HttpOnly' in set_cookie_header}\n"
                result += f" - SameSite: {morsel.get('samesite', 'Not Set')}\n"
        else:
            result += "No Set-Cookie header found.\n"

        # SSL/TLS info
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname
        if parsed_url.scheme == 'https':
            result += check_ssl_info(hostname)
        else:
            result += "\nSSL/TLS Info: Not applicable (HTTP site)\n"

        # Response content type
        result += f"\nContent-Type: {response.headers.get('Content-Type', 'Unknown')}\n"

        # Check if JSON response
        try:
            json_data = response.json()
            result += "\n--- JSON Response ---\n"
            result += str(json_data) + "\n"
        except ValueError:
            result += "\nResponse is not in JSON format.\n"

    except requests.exceptions.RequestException as e:
        result += f"Error connecting to {target_url}: {e}\n"

    print(result)
    if output:
        with open(output, 'a') as f:
            f.write(result)

# Function: Nmap Scan
def nmap_scan(target_url):
    result = f"\n========== Nmap Scan for {target_url} ==========\n"
    try:
        host = target_url.replace("http://", "").replace("https://", "").split('/')[0]
        scanner = nmap.PortScanner()
        scanner.scan(host, '1-1000')
        result += f"\nNmap Scan Results for {host}:\n"
        for host in scanner.all_hosts():
            result += f"\nHost: {host} ({scanner[host].hostname()})\n"
            result += f"State: {scanner[host].state()}\n"
            for proto in scanner[host].all_protocols():
                result += f"\nProtocol: {proto}\n"
                ports = scanner[host][proto].keys()
                for port in ports:
                    result += f"Port: {port}\tState: {scanner[host][proto][port]['state']}\n"
    except Exception as e:
        result += f"Error running Nmap scan on {target_url}: {e}\n"

    print(result)
    if output:
        with open(output, 'a') as f:
            f.write(result)

# Process a single URL
def process_target(target_url):
    print(f"\n===== Scanning Target: {target_url} =====")
    nmap_scan(target_url)
    def_burpsuite(target_url)

# Main workflow
if input_type == 'url':
    url = input("Enter the URL (with http:// or https://): ").strip()
    process_target(url)

elif input_type == 'file':
    file_path = input("Enter the file path containing URLs (one per line): ").strip()
    try:
        with open(file_path, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        for domain in domains:
            process_target(domain)
    except Exception as e:
        print(f"Error reading file: {e}")

else:
    print("Invalid input. Please enter 'url' or 'file'.")

print("\nScanning completed.")
