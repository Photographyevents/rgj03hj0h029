import subprocess
import requests
import time
import os
import re
import json
import gspread
from google.oauth2.service_account import Credentials
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for direct IP scanning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ================== CONFIGURATION ==================
INPUT_FILE = "ips.txt"
TIMEOUT    = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Load Secrets from GitHub Actions Environment
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
GOOGLE_CREDS_JSON  = os.getenv("GOOGLE_SHEETS_CREDS_JSON")

# ================== STRICTOR DETECTION ==================
DASHBOARDS = {
    "jenkins": {
        "name": "Jenkins (OPEN)",
        "ports": [80, 443, 8080, 8443],
        "paths": ["/", "/view/all/"],
        "title_kw": ["Dashboard [Jenkins]"],
        "body_kw": ["Last success", "Build #", "weather-", "project-status"],
        "neg_kw": ["log in", "sign in", "login-form", "j_username", "authentication required"],
        "min_size": 1000,
        "ok_codes": [200],
    },
    "phpmyadmin": {
        "name": "phpMyAdmin (OPEN)",
        "ports": [80, 443, 8080, 8888],
        "paths": ["/phpmyadmin/", "/pma/", "/sql/"],
        "title_kw": ["phpmyadmin"],
        "body_kw": ["pma_navigation", "pma_main--container", "server_databases"],
        "neg_kw": ["pma_username", "input_username", "login_form"],
        "min_size": 1000,
        "ok_codes": [200],
    },
    "grafana": {
        "name": "Grafana",
        "ports": [3000, 80, 443, 8080],
        "paths": ["/api/health", "/login", "/"],
        "title_kw": ["grafana"],
        "body_kw": ["grafana-app", "window.grafanaBootData", "dashboard-grid"],
        "neg_kw": ["setup-page"], 
        "min_size": 500,
        "ok_codes": [200],
    }
}

# ================== HELPERS & REPORTERS ==================

def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=5)
    except:
        pass

def update_google_sheets(row_data):
    if not GOOGLE_CREDS_JSON: return
    try:
        scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        creds_info = json.loads(GOOGLE_CREDS_JSON)
        credentials = Credentials.from_service_account_info(creds_info, scopes=scopes)
        client = gspread.authorize(credentials)
        sheet = client.open("BountyResults").sheet1
        sheet.append_row(row_data)
    except Exception as e:
        print(f"   [!] Google Sheets Error: {e}")

def get_ssl_domain(ip, port):
    try:
        cmd = f"timeout 4 openssl s_client -connect {ip}:{port} -servername {ip} </dev/null 2>/dev/null | openssl x509 -noout -subject"
        res = subprocess.check_output(cmd, shell=True).decode('utf-8')
        match = re.search(r"CN\s*=\s*([^,\n/]+)", res)
        return match.group(1).strip() if match else "No Domain Found"
    except:
        return "No SSL"

# ================== GRAFANA EXPLOIT CHECK ==================

def check_grafana_vulnerabilities(url):
    """Attempts admin:admin login via API for Grafana hits."""
    # Ensure URL doesn't end with a slash for clean concatenation
    base_url = url.split('/login')[0].rstrip('/')
    api_url = f"{base_url}/api/admin/stats"
    
    try:
        # Basic Auth check for admin:admin
        r = requests.get(api_url, auth=('admin', 'admin'), timeout=5, verify=False)
        if r.status_code == 200 and "dashboards" in r.text:
            return "🚨 CRITICAL: Default Credentials (admin:admin) WORK!"
    except:
        pass
    
    # Also check if it's just completely open without login
    try:
        search_url = f"{base_url}/api/search"
        r_open = requests.get(search_url, timeout=5, verify=False)
        if r_open.status_code == 200 and isinstance(r_open.json(), list):
            return "🔓 OPEN ACCESS: Unauthenticated Dashboard List found."
    except:
        pass
        
    return None

# ================== SCANNING LOGIC ==================

def score_response(text, db):
    lower_text = text.lower()
    if any(n_kw in lower_text for n_kw in db.get("neg_kw", [])):
        return False
    if any(kw.lower() in lower_text for kw in db["body_kw"]):
        return True
    return False

def check_ip(ip):
    for key, db in DASHBOARDS.items():
        for port in db["ports"]:
            for path in db["paths"]:
                scheme = "https" if port in [443, 8443] else "http"
                url = f"{scheme}://{ip}:{port}{path}"
                try:
                    r = requests.get(url, timeout=TIMEOUT, verify=False, headers={"User-Agent": USER_AGENT})
                    
                    if r.status_code in db["ok_codes"]:
                        # 1. First check if it's an OPEN dashboard
                        is_open = score_response(r.text, db)
                        vuln_note = None
                        
                        # 2. Special handling for Grafana (Check defaults even if page is a login wall)
                        if key == "grafana":
                            vuln_note = check_grafana_vulnerabilities(url)
                        
                        # Report if it's either open OR has a vulnerability
                        if is_open or vuln_note:
                            domain = get_ssl_domain(ip, port)
                            ts = time.strftime("%Y-%m-%d %H:%M:%S")
                            
                            status_label = vuln_note if vuln_note else f"{db['name']}"
                            msg = f"🎯 HIT: {status_label}\nURL: {url}\nDomain: {domain}"
                            
                            print(f"[!] {msg.replace('\\n', ' | ')}")
                            send_telegram(msg)
                            update_google_sheets([ts, ip, url, status_label, domain])
                            return # Move to next IP
                except:
                    continue

def main():
    if not os.path.exists(INPUT_FILE): return
    with open(INPUT_FILE, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"[*] Scanning {len(ips)} targets...")
    for index, ip in enumerate(ips):
        print(f"[{index+1}/{len(ips)}] Checking {ip}...", end="\r")
        check_ip(ip)

if __name__ == "__main__":
    main()
