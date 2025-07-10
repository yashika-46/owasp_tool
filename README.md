# owasp_tool
## Overview

**owasp_tool** is a modular Python toolkit for automated security assessment of web applications, inspired by the [OWASP Top 10](https://owasp.org/www-project-top-ten/). It provides a menu-driven interface to scan for common vulnerabilities, misconfigurations, and weaknesses in web applications.

## Features
- **XSS Scanner**: Detects reflected/stored XSS vulnerabilities using JavaScript payloads.
- **HTML Injector**: Tests for HTML injection via form fields.
- **JavaScript Injector**: Checks for JavaScript injection vulnerabilities in forms.
- **SQLi Injector**: Scans for SQL injection vulnerabilities using error-based payloads.
- **XSS Injector**: Specialized XSS payload scanner for forms.
- **Cryptographic Failure Checker**: Detects weak cryptography usage and weak TLS ciphers.
- **Security Misconfiguration & Nmap Scanner**: Checks for missing security headers, SSL/TLS issues, and performs port scanning.
- **Broken Link Scanner**: Finds broken links on web pages or lists of URLs.
- **SSRF Detector**: Tests for Server-Side Request Forgery vulnerabilities using custom or default payloads.

## Installation

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd owasp_tool
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   (You may need to install `nmap` separately for the Security Misconfiguration module.)

## Usage

Run the main menu:
```bash
python owasp_tool/main.py
```

Follow the interactive prompts to select a scan type and provide target URLs or files.

## Module Descriptions

- **brokenlink.py**: Scans a single URL or a list of URLs for broken (dead) links and reports their status codes.
- **cryp_fail_checker.py**: Checks web pages and TLS connections for weak cryptographic algorithms (e.g., MD5, SHA1, RC4) and weak ciphers.
- **htmlinjector.py**: Attempts HTML injection in forms using common payloads to identify unsanitized input vulnerabilities.
- **jsinjector.py**: Tests for JavaScript injection vulnerabilities in form fields using crafted JS payloads.
- **security_misconfig.py**: Checks for missing security headers, inspects SSL/TLS certificates, and runs an Nmap port scan on the target.
- **sqliinjector.py**: Scans forms for SQL injection vulnerabilities using error-based payloads and detects SQL error messages in responses.
- **ssrf_detector.py**: Tests for SSRF vulnerabilities by injecting payloads into URLs and checking for unexpected responses.
- **xss_scanner.py**: Scans for XSS vulnerabilities in forms using JavaScript payloads and reports if payloads are reflected in responses.
- **xssinjector.py**: Specialized scanner for XSS vulnerabilities using a set of XSS payloads in form fields.

## Example

1. Start the tool:
   ```bash
   python owasp_tool/main.py
   ```
2. Choose a scan (e.g., `1` for XSS Scanner).
3. Enter the target URL or file as prompted.
4. View results in the console or in the specified output file.

## Requirements
- Python 3.7+
- `requests`, `beautifulsoup4`, `nmap` (for some modules), `html`, `ssl`, `socket`

Install all dependencies with:
```bash
pip install -r requirements.txt
```

## Notes
- Some modules require internet access and/or network permissions.
- For Nmap scanning, ensure `nmap` is installed on your system.
- Output can be saved to files for later analysis.

## Disclaimer
This tool is for educational and authorized security testing only. Do not use it on systems without permission. 
