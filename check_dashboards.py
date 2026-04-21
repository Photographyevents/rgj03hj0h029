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

# ================== STRICTER DETECTION ==================
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

# ================== REPORTERS & FALLBACKS ==================

def send_telegram(message):
    """Sends an HTML formatted message to Telegram."""
    if not TELEGRAM_BOT_TOKEN: 
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        r = requests.post(
            url, 
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}, 
            timeout=8
        )
        return r.json().get("ok", False)
    except Exception as e:
        print(f"   [!] Telegram error: {e}")
        return False

def telegram_fallback(row_data, error_reason):
    """Formats the data beautifully if Sheets fails."""
    ts, ip, url, status_label, domain = row_data
    msg = (
        f"⚠️ <b>Google Sheets Sync Failed</b>\n"
        f"<i>Reason: {error_reason}</i>\n\n"
        f"🚨 <b>Fallback Alert — Dashboard Found</b>\n"
        f"<b>Domain:</b> <code>{domain}</code>\n"
        f"<b>IP:</b> <code>{ip}</code>\n"
        f"<b>Status/CVE:</b> {status_label}\n"
        f"<b>URL:</b> {url}\n"
    )
    send_telegram(msg)

def update_google_sheets(row_data):
    """Attempts to write to Sheets, triggers Telegram fallback on failure."""
    if not GOOGLE_CREDS_JSON:
        print("   [!] No Sheets credentials found. Routing directly to Telegram.")
        telegram_fallback(row_data, "GOOGLE_SHEETS_CREDS_JSON is empty or missing.")
        return

    try:
        scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        creds_info = json.loads(GOOGLE_CREDS_JSON)
        credentials = Credentials.from_service_account_info(creds_info, scopes=scopes)
        client = gspread.authorize(credentials)
        sheet = client.open("BountyResults").sheet1
        sheet.append_row(row_data)
        print("   [+] Result synced to Google Sheets.")
    except Exception as e:
        print(f"   [!] Google Sheets Error: {e}")
        print("   [+] Triggering Telegram Fallback...")
        telegram_fallback(row_data, str(e))

# ================== OSINT & SSL ==================

def get_ssl_domain(ip, port):
    try:
        cmd = f"timeout 4 openssl s_client -connect {ip}:{port} -servername {ip} </dev/null 2>/dev/null | openssl x509 -noout -subject"
        res = subprocess.check_output(cmd, shell=True).decode('utf-8')
        match = re.search(r"CN\s*=\s*([^,\n/]+)", res)
        # Strip wildcard prefixes (*.example.com -> example.com)
        return match.group(1).strip().lstrip("*").lstrip(".") if match else "No Domain Found"
    except:
        return "No SSL"

# ================== GRAFANA EXPLOIT CHECK ==================

def check_grafana_vulnerabilities(url):
    """Checks for admin:admin AND the new CVE-2026-27877 Credential Leak."""
    base_url = url.split('/login')[0].rstrip('/')
    results = []

    # 1. Check for admin:admin
    try:
        api_url = f"{base_url}/api/admin/stats"
        r = requests.get(api_url, auth=('admin', 'admin'), timeout=5, verify=False)
        if r.status_code == 200 and "dashboards" in r.text:
            results.append("🚨 CRITICAL: admin:admin works")
    except: pass

    # 2. Check for CVE-2026-27877 (Public Dashboard Credential Leak)
    try:
        public_api = f"{base_url}/api/public-dashboards"
        r_cve = requests.get(public_api, timeout=5, verify=False)
        if r_cve.status_code == 200:
            data = r_cve.text
            if '"secureJsonData"' in data or '"password"' in data:
                 results.append("🔥 EXPLOIT: CVE-2026-27877 Credential Leak detected!")
            else:
                 results.append("🔓 OPEN: Public Dashboards Enabled (Review manually)")
    except: pass

    return " | ".join(results) if results else None

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
                        is_open = score_response(r.text, db)
                        vuln_note = None
                        
                        if key == "grafana":
                            vuln_note = check_grafana_vulnerabilities(url)
                        
                        if is_open or vuln_note:
                            domain = get_ssl_domain(ip, port)
                            ts = time.strftime("%Y-%m-%d %H:%M:%S")
                            status_label = vuln_note if vuln_note else f"{db['name']}"
                            
                            print(f"\n[!] 🎯 HIT: {status_label} | {url} | Domain: {domain}")
                            
                            # Only send standard Telegram hit if it's a critical vulnerability
                            if vuln_note:
                                send_telegram(
                                    f"🔥 <b>CRITICAL VULN FOUND</b>\n"
                                    f"<b>Domain:</b> <code>{domain}</code>\n"
                                    f"<b>IP:</b> <code>{ip}</code>\n"
                                    f"<b>Vuln:</b> {status_label}\n"
                                    f"<b>URL:</b> {url}"
                                )
                            
                            # Log to Sheets (which triggers fallback if needed)
                            update_google_sheets([ts, ip, url, status_label, domain])
                            return 
                except:
                    continue

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"File {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, "r") as f:
        ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"[*] Scanning {len(ips)} targets...")
    for index, ip in enumerate(ips):
        print(f"[{index+1}/{len(ips)}] Checking {ip}...", end="\r")
        check_ip(ip)
    print("\n[*] Scan complete.")

if __name__ == "__main__":
    main()
