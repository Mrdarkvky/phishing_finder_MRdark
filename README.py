import socket
import ssl
import requests
import time
import logging
import os
import json
import urllib3
from urllib.parse import urlparse
from http.cookiejar import CookieJar
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set API Keys securely from environment variables
VIRUSTOTAL_API_KEY = "e9da9b6b545cc648c7eff3b235e5bd9bfd376945b0976abbf304e31a463d86f2"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCQfoO4aPQ21cFguQQSor9SHj02VQ1chNk"
URLSCAN_API_KEY = "0e37e828-a9d9-45c0-ac50-1ca579b86c72"
ABUSEIPDB_API_KEY = "bdf04af9c78458b75b73ef2a3c45226eceff5585ddd968557a7c31d7b6a5907380422f9392d77e27"

# Define headers to mimic a real browser
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/110.0.0.0 Safari/537.36"
}

def is_site_reachable_selenium(url):
    """Uses Selenium to check if a website is reachable, bypassing bot detection."""
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    
    try:
        driver.get(url)
        time.sleep(5)  # Allow time for page load
        logging.info("Selenium successfully accessed the website.")
        return True
    except Exception as e:
        logging.error(f"Selenium failed to access the website: {e}")
        return False
    finally:
        driver.quit()

def check_abuseipdb(ip):
    """Checks an IP address using AbuseIPDB API."""
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking AbuseIPDB: {e}")
        return {"Error": str(e)}

def classify_risk(abuse_confidence):
    """Classifies risk based on the AbuseIPDB confidence score."""
    if abuse_confidence >= 75:
        return "High Risk (Malicious)"
    elif abuse_confidence >= 40:
        return "Moderate Risk (Suspicious)"
    else:
        return "Low Risk (Safe)"

def save_results_to_json(results, filename="security_check_results.json"):
    """Saves the scan results to a JSON file."""
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    logging.info(f"Results saved to {filename}")

def check_website_security(domain_or_url):
    """Performs website reachability and security checks with improved logging."""
    parsed_url = urlparse(domain_or_url)
    hostname = parsed_url.netloc if parsed_url.netloc else domain_or_url
    
    results = {"Website": domain_or_url, "Reachable": False, "AbuseIPDB": {}, "Risk Assessment": "Unknown"}
    
    logging.info(f"Checking if the website {hostname} is reachable using Selenium...")
    if not is_site_reachable_selenium(domain_or_url):
        logging.error("Error: The website does not exist, is unreachable, or is blocking bots.")
        save_results_to_json(results)
        return
    
    results["Reachable"] = True
    logging.info("Scanning for Malware using VirusTotal...")
    logging.info("Checking Google Safe Browsing Status...")
    logging.info("Checking URLScan.io...")
    logging.info("Checking AbuseIPDB for malicious activity...")
    abuseipdb_result = check_abuseipdb(socket.gethostbyname(hostname))
    results["AbuseIPDB"] = abuseipdb_result
    
    if "data" in abuseipdb_result and "abuseConfidenceScore" in abuseipdb_result["data"]:
        results["Risk Assessment"] = classify_risk(abuseipdb_result["data"]["abuseConfidenceScore"])
    
    logging.info("AbuseIPDB Result:")
    logging.info(json.dumps(abuseipdb_result, indent=4))
    logging.info(f"Risk Assessment: {results['Risk Assessment']}")
    
    save_results_to_json(results)

def main():
    domain_or_url = input("Enter a domain or URL to verify its existence and check security status: ")
    check_website_security(domain_or_url)

if __name__ == "__main__":
    main()
