import socket
import ssl
import requests
import time
import logging
import os
from datetime import datetime
from urllib.parse import urlparse


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


VIRUSTOTAL_API_KEY = "e9da9b6b545cc648c7eff3b235e5bd9bfd376945b0976abbf304e31a463d86f2"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCQfoO4aPQ21cFguQQSor9SHj02VQ1chNk"

def is_site_reachable(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        if not ip_address:
            return False
        for scheme in ["http", "https"]:
            try:
                response = requests.head(f"{scheme}://{hostname}", timeout=5, allow_redirects=True)
                if response.status_code < 400:
                    return True
            except requests.RequestException:
                continue
    except (socket.gaierror, socket.herror):
        return False
    return False

def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {"Error": "VirusTotal API key not configured."}
    url_vt = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"url": url}
    try:
        response = requests.post(url_vt, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        if "data" in response_json:
            analysis_id = response_json["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            time.sleep(5)
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_response.raise_for_status()
            analysis_json = analysis_response.json()
            if "data" in analysis_json and "attributes" in analysis_json["data"]:
                stats = analysis_json["data"]["attributes"]["stats"]
                is_safe = "Safe" if stats.get("malicious", 0) == 0 and stats.get("suspicious", 0) == 0 else "Unsafe"
                return {"Malicious": stats.get("malicious", 0), "Suspicious": stats.get("suspicious",0), "Harmless": stats.get("harmless",0), "Undetected": stats.get("undetected", 0), "Overall Status": is_safe}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking VirusTotal: {e}")
        return {"Error": str(e)}
    return None

def check_google_safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"Error": "Google Safe Browsing API key not configured."}
    url_gsb = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    headers = {"Content-Type": "application/json"}
    data = {
        "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(url_gsb, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        if "matches" in result:
            return {"Safe Browsing Status": "Unsafe"}
        return {}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking Google Safe Browsing: {e}")
        return {"Error": str(e)}

def check_website_and_url(domain_or_url):
    parsed_url = urlparse(domain_or_url)
    hostname = parsed_url.netloc if parsed_url.netloc else domain_or_url
    print(f"\nVerifying if the site {hostname} exists...")
    if not is_site_reachable(hostname):
        print("Error: The website does not exist or is unreachable.")
        return
    print("\nChecking for Malware with VirusTotal...")
    malware_info = check_virustotal(domain_or_url)
    for key, value in malware_info.items():
        print(f"{key}: {value}")

def main():
    domain_or_url = input("Enter the domain or URL to verify its existence and check security status: ")
    check_website_and_url(domain_or_url)

if __name__ == "__main__":
    main()
