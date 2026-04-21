import subprocess
import requests
import time
import os
import re
import argparse
import json
import gspread
import concurrent.futures
from google.oauth2.service_account import Credentials
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
load_dotenv()

# ================== CONFIGURATION ==================
INPUT_FILE      = "ips.txt"
TIMEOUT         = 10
MAX_WORKERS     = 20  # How many IPs to check at once
USER_AGENT      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
GOOGLE_CREDS_JSON  = os.getenv("GOOGLE_SHEETS_CREDS_JSON")

# ================== DETECTION DICTIONARY ==================
DASHBOARDS = {
    "grafana": {
        "name": "Grafana",
        "ports": [3000, 80, 443, 8080],
        "paths": ["/", "/api/health", "/login"],
        "title_kw": ["grafana"],
        "body_kw": ["grafana-app", "window.grafanaBootData", "dashboard-grid"],
        "neg_kw": ["setup-page"], 
        "min_size": 500,
        "ok_codes": [200],
    },
    "jenkins": {
        "name": "Jenkins",
        "ports": [8080, 80, 443],
        "paths": ["/", "/view/all/"],
        "title_kw": ["jenkins"],
        "body_kw": ["Last success", "Build #", "weather-", "project-status"],
        "neg_kw": ["log in", "sign in", "login-form", "j_username"],
        "min_size": 300,
        "ok_codes": [200, 403],
    },
    "phpmyadmin": {
        "name": "phpMyAdmin",
        "ports": [80, 443, 8080, 8888],
        "paths": ["/phpmyadmin/", "/pma/", "/sql/"],
        "title_kw": ["phpmyadmin"],
        "body_kw": ["pma_navigation", "pma_main--container", "server_databases"],
        "neg_kw": ["pma_username", "input_username", "login_form"],
        "min_size": 1000,
        "ok_codes": [200],
    }
}

# ================== REPORTERS ==================

def send_telegram(message: str):
    if not TELEGRAM_BOT_TOKEN: return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=8
        )
    except: pass

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
        # Fallback to Telegram if Sheets fails
        send_telegram(f"<b>Sheets Fail:</b> {row_data[1]} | {row_data[3]}\nError: {str(e)}")

# ================== OSINT & VULN CHECKS ==================

def get_ssl_domain(ip, port):
    try:
        cmd = f"timeout 3 openssl s_client -connect {ip}:{port} -servername {ip} 2>/dev/null | openssl x509 -noout -subject"
        res = subprocess.check_output(cmd, shell=True).decode('utf-8')
        match = re.search(r"CN\s*=\s*([^,\n/]+)", res)
        return match.group(1).strip().lstrip("*").lstrip(".") if match else "No Domain Found"
    except: return "No SSL"

def check_grafana_vulnerabilities(url):
    base_url = url.split('/login')[0].rstrip('/')
    results = []
    try:
        r = requests.get(f"{base_url}/api/admin/stats", auth=('admin', 'admin'), timeout=5, verify=False)
        if r.status_code == 200 and "dashboards" in r.text:
            results.append("🚨 admin:admin works")
    except: pass
    try:
        r_cve = requests.get(f"{base_url}/api/public-dashboards", timeout=5, verify=False)
        if r_cve.status_code == 200 and ('"secureJsonData"' in r_cve.text or '"password"' in r_cve.text):
            results.append("🔥 CVE-2026-27877 Leak!")
    except: pass
    return " | ".join(results) if results else None

# ================== CORE SCANNER ==================

def check_ip(ip, tags):
    for tag in tags:
        db = DASHBOARDS[tag]
        for port in db["ports"]:
            for path in db["paths"]:
                url = f"{'https' if port in [443, 8443] else 'http'}://{ip}:{port}{path}"
                try:
                    r = requests.get(url, timeout=TIMEOUT, verify=False, headers={"User-Agent": USER_AGENT})
                    if r.status_code in db["ok_codes"]:
                        # Basic Keyword Match
                        if not any(kw.lower() in r.text.lower() for kw in db["body_kw"]): continue
                        if any(n_kw in r.text.lower() for n_kw in db.get("neg_kw", [])): continue
                        
                        vuln_note = check_grafana_vulnerabilities(url) if tag == "grafana" else None
                        domain = get_ssl_domain(ip, port)
                        ts = time.strftime("%Y-%m-%d %H:%M:%S")
                        status = vuln_note if vuln_note else db["name"]
                        
                        print(f"🎯 HIT: {ip} | {status}")
                        
                        if vuln_note:
                            send_telegram(f"🔥 <b>VULN:</b> {status}\n<b>IP:</b> {ip}\n<b>URL:</b> {url}")
                        
                        update_google_sheets([ts, ip, url, status, domain])
                        return
                except: continue

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tags", type=str, default="all")
    args = parser.parse_args()

    selected_tags = list(DASHBOARDS.keys()) if args.tags.lower() == "all" else [t.strip().lower() for t in args.tags.split(",")]
    
    if not os.path.exists(INPUT_FILE): return
    with open(INPUT_FILE) as f:
        ips = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    print(f"[*] Multi-threaded Scan: {len(ips)} IPs | Threads: {MAX_WORKERS}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(check_ip, ip, selected_tags) for ip in ips]
        concurrent.futures.wait(futures)

    print("\n[*] Scan Complete.")

if __name__ == "__main__":
    main()
