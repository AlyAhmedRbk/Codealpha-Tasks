import requests
from bs4 import BeautifulSoup
import json
from urllib.parse import urljoin
import sys

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def fetch(url):
    try:
        return requests.get(url)
    except Exception as e:
        print(f"Error fetching URL: {e}")
        return None

def check_security_headers(resp):
    missing = []
    present = {}

    for h in SECURITY_HEADERS:
        if h in resp.headers:
            present[h] = resp.headers[h]
        else:
            missing.append(h)

    return {"present": present, "missing": missing}

def check_cookies(resp):
    issues = []
    for cookie in resp.cookies:
        if not cookie.secure:
            issues.append({"cookie": cookie.name, "issue": "Missing Secure flag"})
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append({"cookie": cookie.name, "issue": "Missing HttpOnly flag"})
    return issues

def check_robots(base_url):
    robots = urljoin(base_url, "/robots.txt")
    r = fetch(robots)
    if r and r.status_code == 200:
        return r.text
    return None

def find_admin_links(html):
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        if "admin" in tag["href"].lower():
            links.append(tag["href"])
    return links

def scan(url):
    resp = fetch(url)
    if not resp:
        return {"error": "target not reachable"}

    result = {
        "target": url,
        "status": resp.status_code,
        "security_headers": check_security_headers(resp),
        "cookie_issues": check_cookies(resp),
        "robots_file": check_robots(url),
        "admin_links_found": find_admin_links(resp.text),
        "server": resp.headers.get("Server")
    }

    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python simple_scanner.py <url>")
        sys.exit()

    target = sys.argv[1]
    output = scan(target)
    print(json.dumps(output, indent=2))
