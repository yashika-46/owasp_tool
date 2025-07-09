import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Ask user for input type
input_type = input("Do you want to scan a single URL or a file? (enter 'url' or 'file'): ").strip().lower()

# Ask for output filename
output = input("Enter the output filename to save results (leave blank to skip saving): ").strip()

# Function to check if URL is valid
def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

# Function to find broken links on a given URL
def find_broken_links(base_url):
    result = f"\n========== Broken Link Scan for {base_url} ==========\n"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
        }
        response = requests.get(base_url, headers=headers, timeout=20)
        response.raise_for_status()
    except requests.RequestException as e:
        result += f"Failed to access {base_url}: {e}\n"
        print(result)
        if output:
            with open(output, 'a') as f:
                f.write(result)
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()

    for tag in soup.find_all('a', href=True):
        href = tag['href']
        full_url = urljoin(base_url, href)
        if is_valid_url(full_url):
            links.add(full_url)

    broken_links = []
    for link in links:
        try:
            r = requests.get(link, timeout=5)
            if r.status_code >= 400:
                broken_links.append((link, r.status_code))
        except requests.RequestException:
            broken_links.append((link, 'No Response'))

    if broken_links:
        for bl in broken_links:
            result += f"Broken Link: {bl[0]} - Status: {bl[1]}\n"
    else:
        result += "No broken links found.\n"

    print(result)
    if output:
        with open(output, 'a') as f:
            f.write(result)

# Main workflow
if input_type == 'url':
    url = input("Enter the URL (with http:// or https://): ").strip()
    find_broken_links(url)

elif input_type == 'file':
    file_path = input("Enter the file path containing URLs (one per line): ").strip()
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            find_broken_links(url)
    except Exception as e:
        print(f"Error reading file: {e}")

else:
    print("Invalid input. Please enter 'url' or 'file'.")

print("\nBroken link scanning completed.")
