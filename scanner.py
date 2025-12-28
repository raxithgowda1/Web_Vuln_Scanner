import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Load payloads
def load_payloads(file):
    with open(file, "r") as f:
        return f.read().splitlines()

sqli_payloads = load_payloads("sqli_payloads.txt")
xss_payloads = load_payloads("xss_payloads.txt")
redirect_payloads = load_payloads("redirect_payloads.txt")

report = []

def get_parameters(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def test_sqli(url, params):
    for param in params:
        for payload in sqli_payloads:
            new_params = params.copy()
            new_params[param] = payload
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(urlparse(url)._replace(query=new_query))
            r = requests.get(test_url)
            if "sql" in r.text.lower() or "syntax" in r.text.lower():
                report.append(f"[SQLi] Vulnerable Parameter: {param} | Payload: {payload}")

def test_xss(url, params):
    for param in params:
        for payload in xss_payloads:
            new_params = params.copy()
            new_params[param] = payload
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(urlparse(url)._replace(query=new_query))
            r = requests.get(test_url)
            if payload in r.text:
                report.append(f"[XSS] Vulnerable Parameter: {param} | Payload: {payload}")

def test_open_redirect(url, params):
    for param in params:
        for payload in redirect_payloads:
            new_params = params.copy()
            new_params[param] = payload
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(urlparse(url)._replace(query=new_query))
            r = requests.get(test_url, allow_redirects=False)
            if r.status_code in [301, 302]:
                report.append(f"[Open Redirect] Parameter: {param} | Redirects to {payload}")

def main():
    target_url = input("Enter target URL (with parameters): ")
    params = get_parameters(target_url)

    if not params:
        print("No parameters found!")
        return

    print("[+] Scanning for SQL Injection...")
    test_sqli(target_url, params)

    print("[+] Scanning for XSS...")
    test_xss(target_url, params)

    print("[+] Scanning for Open Redirect...")
    test_open_redirect(target_url, params)

    with open("report.txt", "w") as f:
        for line in report:
            f.write(line + "\n")

    print("\nScan Complete! Check report.txt")

if __name__ == "__main__":
    main()