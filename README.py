import socket
import ssl
import requests
import time
import logging
import os
from datetime import datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import messagebox
import pyperclip
import joblib
import re
from Levenshtein import distance as levenshtein_distance
import pandas as pd
import numpy as np


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='phishing_detection.log',
    filemode='a' 
)

VIRUSTOTAL_API_KEY = "e9da9b6b545cc648c7eff3b235e5bd9bfd376945b0976abbf304e31a463d86f2"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCQfoO4aPQ21cFguQQSor9SHj02VQ1chNk"

try:
    model = joblib.load('phishing_model_large.pkl')
except FileNotFoundError:
    logging.error("Model file 'phishing_model_large.pkl' not found. Please train the model first.")
    raise


legit_domains = {
    'google.com': ['142.250.190.78'], 'facebook.com': ['157.240.241.35'], 'amazon.com': ['52.94.236.248'],
    'microsoft.com': ['20.112.250.133'], 'apple.com': ['17.253.144.10'], 'twitter.com': ['104.244.42.129'],
    'linkedin.com': ['108.174.10.10'], 'paypal.com': ['173.0.88.66'], 'netflix.com': ['52.94.237.243'],
    'instagram.com': ['157.240.241.63'], 'youtube.com': ['142.250.190.78'],
    'deepseek.com': ['104.21.27.108']  
}

def is_site_reachable(url):
    """
    Check if a website is reachable by mimicking a browser request.
    Returns True if the site responds with any HTTP status < 500, False if no response.
    """
    if not url.startswith("http"):
        url = f"https://{url}"


    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://www.google.com',
        'DNT': '1',  
        'Cache-Control': 'max-age=0'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        status_code = response.status_code
        logging.info(f"Request to {url}: Status code {status_code}")
        

        return status_code < 500
    except requests.RequestException as e:
        logging.error(f"Reachability check failed for {url}: {str(e)}")
        return False

def check_ssl_validity(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                if 'commonName' not in subject or subject['commonName'] != hostname:
                    return False, "SSL certificate mismatch"
                return True, "Valid SSL"
    except (ssl.SSLError, socket.error) as e:
        return False, f"SSL error: {str(e)}"

def check_homograph(url):
    ascii_url = url.encode().decode('ascii', 'ignore')
    if ascii_url != url:
        return True, "Contains non-ASCII characters (possible homograph)"
    return False, "No homographs detected"

def resolve_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        trusted_ips = legit_domains.get(hostname, [])
        if trusted_ips and ip not in trusted_ips:
            return False, f"IP {ip} not in trusted list: {trusted_ips}"
        return True, f"IP resolved: {ip}"
    except socket.gaierror as e:
        return False, f"DNS resolution error: {str(e)}"

def extract_features(url):
    parsed = urlparse(url)
    netloc = parsed.netloc if parsed.netloc else url
    domain = netloc.split(':')[0]
    buzzwords = ['quantum', 'ai', 'mfa', 'iot', 'secure', 'login', 'update', '5g', 'cloud', 'crypto']
    shortened_services = ['tinyurl.com', 'bit.ly', 't.co', 'short.link', 'ow.ly']
    
    ssl_valid, ssl_msg = check_ssl_validity(domain) if parsed.scheme == 'https' else (True, "No HTTPS")
    homograph_detected, homo_msg = check_homograph(url)
    ip_valid, ip_msg = resolve_ip(domain)
    
    path_query = (parsed.path + parsed.query).lower()
    char_counts = {c: path_query.count(c) for c in set(path_query) if c.isalnum()}
    total_chars = sum(char_counts.values())
    entropy = -sum((count / total_chars) * np.log2(count / total_chars) for count in char_counts.values()) if total_chars > 0 else 0
    
    features = {
        'length': len(url),
        'num_subdomains': len(netloc.split('.')) - 1 if netloc else 0,
        'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', netloc) else 0,
        'uses_https': 1 if parsed.scheme == 'https' else 0,
        'num_dots': url.count('.'),
        'num_slashes': url.count('/'),
        'has_suspicious_chars': 1 if any(c in url.lower() for c in '!@#$%^&*') else 0,
        'min_domain_similarity': min([levenshtein_distance(domain.lower(), legit.lower()) 
                                     for legit in legit_domains.keys()] or [float('inf')]) / max(len(domain), 1),
        'ssl_invalid': 0 if ssl_valid else 1,
        'homograph_detected': 1 if homograph_detected else 0,
        'ip_untrusted': 0 if ip_valid else 1,
        'has_buzzwords': 1 if any(bw in url.lower() for bw in buzzwords) else 0,
        'is_shortened': 1 if any(srv in netloc.lower() for srv in shortened_services) else 0,
        'keyword_entropy': entropy,
        'has_query_params': 1 if parsed.query else 0
    }
    details = f"SSL: {ssl_msg}, Homograph: {homo_msg}, IP: {ip_msg}"
    return features, details

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
                return {"Malicious": stats.get("malicious", 0), "Suspicious": stats.get("suspicious", 0), 
                        "Harmless": stats.get("harmless", 0), "Undetected": stats.get("undetected", 0), 
                        "Overall Status": is_safe}
    except requests.RequestException as e:
        logging.error(f"Error checking VirusTotal: {e}")
        return {"Error": str(e)}
    return {"Error": "No valid response from VirusTotal"}

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
        return {"Safe Browsing Status": "Unsafe" if "matches" in result else "Safe"}
    except requests.RequestException as e:
        logging.error(f"Error checking Google Safe Browsing: {e}")
        return {"Error": str(e)}

def check_website_and_url(domain_or_url):
    parsed_url = urlparse(domain_or_url)
    hostname = parsed_url.netloc if parsed_url.netloc else domain_or_url
    logging.info(f"Verifying reachability of {hostname}")
    
    if not is_site_reachable(domain_or_url):
        return "Error: The website does not exist or is unreachable."
    
    ai_result, ai_details = predict_phishing(domain_or_url)
    vt_result = check_virustotal(domain_or_url)
    gsb_result = check_google_safe_browsing(domain_or_url)
    
    is_unsafe = (ai_result == "Phishing" or
                 (vt_result and vt_result.get("Overall Status") == "Unsafe") or
                 (gsb_result and gsb_result.get("Safe Browsing Status") == "Unsafe"))
    final_result = "Unsafe" if is_unsafe else "Safe"
    
    result = f"AI Prediction: {ai_result}\n"
    if vt_result and "Error" not in vt_result:
        result += f"VirusTotal: {vt_result.get('Overall Status')} (Malicious: {vt_result.get('Malicious')}, Suspicious: {vt_result.get('Suspicious')})\n"
    else:
        result += f"VirusTotal: {vt_result.get('Error', 'No result')}\n"
    if gsb_result and "Error" not in gsb_result:
        result += f"Google Safe Browsing: {gsb_result.get('Safe Browsing Status')}\n"
    else:
        result += f"Google Safe Browsing: {gsb_result.get('Error', 'No result')}\n"
    result += f"Final Result: {final_result}\nDetails: {ai_details}"
    return result

def predict_phishing(url):
    features, details = extract_features(url)
    feature_df = pd.DataFrame([features])
    prediction = model.predict(feature_df)
    return "Phishing" if prediction[0] == 1 else "Legitimate", details

root = tk.Tk()
root.title("Real-Time Phishing Detector")
root.geometry("400x300")

label = tk.Label(root, text="Enter URL to Check:")
label.pack(pady=5)

entry = tk.Entry(root, width=50)
entry.pack(pady=5)

def check_url():
    url = entry.get()
    if url:
        start_time = time.time()
        result = check_website_and_url(url)
        elapsed_time = time.time() - start_time
        messagebox.showinfo("Phishing Check Results", f"{result}\n\nTime taken: {elapsed_time:.2f} seconds")
        logging.info(f"Checked URL: {url}, Result: {result}, Time: {elapsed_time:.2f} seconds")
    else:
        messagebox.showwarning("Input Error", "Please enter a URL.")

button = tk.Button(root, text="Check URL", command=check_url)
button.pack(pady=5)

last_clipboard = ""
def monitor_clipboard():
    global last_clipboard
    current_clipboard = pyperclip.paste()
    if (current_clipboard != last_clipboard and 
        (current_clipboard.startswith("http") or current_clipboard.startswith("www"))):
        start_time = time.time()
        result = check_website_and_url(current_clipboard)
        elapsed_time = time.time() - start_time
        messagebox.showinfo("Clipboard URL Check", f"Checked: {current_clipboard}\n\n{result}\n\nTime taken: {elapsed_time:.2f} seconds")
        logging.info(f"Clipboard URL: {current_clipboard}, Result: {result}, Time: {elapsed_time:.2f} seconds")
        last_clipboard = current_clipboard
    root.after(1000, monitor_clipboard)

monitor_clipboard()

def main():
    domain_or_url = input("Enter the domain or URL to verify its existence and check security status: ")
    result = check_website_and_url(domain_or_url)
    print(result)

if __name__ == "__main__":
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nSwitching to command-line mode...")
        main()
