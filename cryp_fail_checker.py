import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import ssl
import socket

HEADERS = {"User-Agent": "Mozilla/5.0"}
WEAK_CRYPTO_KEYWORDS = [
    r"\bmd5\b",
    r"\bsha1\b",
    r"\brc4\b",
    r"\b3des\b",
    r"\bdes-(ecb|cbc|cfb|ofb|ctr)\b"
]

def log_result(message, save_file=None):
    print(message)
    if save_file:
        with open(save_file, "a", encoding="utf-8") as f:
            f.write(message + "\n")

def scan_for_weak_crypto_in_html(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        html = response.text
        found_crypto = [k for k in WEAK_CRYPTO_KEYWORDS if re.search(k, html, re.IGNORECASE)]
        return found_crypto
    except requests.RequestException as e:
        return None

def scan_tls_weak_ciphers(hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_ciphers("ALL")
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if any(re.search(k, str(cipher).lower()) for k in WEAK_CRYPTO_KEYWORDS):
                    return [str(cipher)]
    except Exception:
        return None

def scan_for_cryptographic_failures(url, save_file=None):
    log_result(f"\n[+] Scanning for Cryptographic Failures: {url}", save_file)
    parsed = urlparse(url)
    found = False

    found_crypto = scan_for_weak_crypto_in_html(url)
    if found_crypto:
        found = True
        log_result(f"[+] Weak crypto keywords found in page: {', '.join(found_crypto)}", save_file)

    if parsed.scheme == "https":
        tls_weak = scan_tls_weak_ciphers(parsed.hostname)
        if tls_weak:
            found = True
            log_result(f"[+] Weak TLS Cipher detected: {', '.join(tls_weak)}", save_file)

    if not found:
        log_result("[+] No cryptographic failures found.", save_file)
    log_result("[+] Scan Complete.\n", save_file)

def load_urls_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

if __name__ == "__main__":
    input_type = input("Scan a single URL or from file? (url/file): ").strip().lower()
    save_choice = input("Save output to file? (yes/no): ").strip().lower()
    save_file = input("Enter filename to save results: ").strip() if save_choice == "yes" else None

    urls = []
    if input_type == 'url':
        urls = [input("Enter the full URL (e.g., https://example.com): ").strip()]
    elif input_type == 'file':
        urls = load_urls_from_file(input("Enter path to URL list file: ").strip())
    else:
        print("Please enter 'url' or 'file'.")
        exit()

    for url in urls:
        try:
            requests.head(url, headers=HEADERS, timeout=10)
            scan_for_cryptographic_failures(url, save_file)
        except requests.RequestException:
            log_result(f"[-] Domain not reachable or site is down: {url}", save_file)
        except Exception as e:
            log_result(f"[!] Error scanning {url}: {e}", save_file)
