import subprocess
import requests
import time
import os
import re
import argparse
import signal
import json
import gspread
from google.oauth2.service_account import Credentials
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

# Disable SSL warnings and load local .env if running on Mac
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
load_dotenv()

# ================== CONFIGURATION ==================
INPUT_FILE      = "ips.txt"
CONFIRMED_FILE  = "confirmed_dashboards.txt"
NO_DOMAIN_FILE  = "no_domain_dashboards.txt"
MANUAL_FILE     = "manual_check.txt"
TIMEOUT         = 10
USER_AGENT      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Load Secrets from Environment (Local or GitHub Actions)
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
        "ports": [8080, 80, 443, 8443],
        "paths": ["/", "/view/all/"],
        "title_kw": ["jenkins"],
        "body_kw": ["Last success", "Build #", "weather-", "project-status", "x-jenkins"],
        "neg_kw": ["log in", "sign in", "login-form", "j_username", "authentication required"],
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
    },
    "prometheus": {
        "name": "Prometheus",
        "ports": [9090],
        "paths": ["/", "/graph"],
        "title_kw": ["prometheus"],
        "body_kw": ["prometheus", "time series", "tsdb", "/metrics"],
        "neg_kw": [],
        "min_size": 500,
        "ok_codes": [200],
    },
    "kibana": {
        "name": "Kibana",
        "ports": [5601],
        "paths": ["/", "/app/home"],
        "title_kw": ["kibana", "elastic"],
        "body_kw": ["kibana", "kbn-name", "elastic"],
        "neg_kw": [],
        "min_size": 500,
        "ok_codes": [200, 302],
    },
    "portainer": {
        "name": "Portainer",
        "ports": [9000, 9443],
        "paths": ["/", "/api/status"],
        "title_kw": ["portainer"],
        "body_kw": ["portainer", "apiversion"],
        "neg_kw": [],
        "min_size": 100,
        "ok_codes": [200],
    },
    "glances": {
        "name": "Glances",
        "ports": [61208, 61209],
        "paths": ["/", "/api/3/all"],
        "title_kw": ["glances"],
        "body_kw": ["glances", '"cpu"', '"mem"'],
        "neg_kw": [],
        "min_size": 200,
        "ok_codes": [200],
    },
    "elasticsearch": {
        "name": "Elasticsearch",
        "ports": [9200],
        "paths": ["/", "/_cluster/health"],
        "title_kw": [],
        "body_kw": ['"cluster_name"', '"lucene_version"', '"tagline"'],
        "neg_kw": [],
        "min_size": 50,
        "ok_codes": [200],
    },
    "airflow": {
        "name": "Apache Airflow",
        "ports": [8080],
        "paths": ["/", "/login"],
        "title_kw": ["airflow"],
        "body_kw": ["airflow", "csrf_token", "dag_id"],
        "neg_kw": ["sign in"],
        "min_size": 300,
        "ok_codes": [200],
    }
}

running = True

def signal_handler(sig, frame):
    global running
    print("\n\n[!] Ctrl+C detected — saving progress and exiting...")
    running = False

signal.signal(signal.SIGINT, signal_handler)

# ================== OSINT & DOMAIN LOGIC ==================

def get_ssl_cn(ip: str, port: int = 443) -> dict | None:
    """Extracts the CN from the SSL certificate to identify the company."""
    try:
        cmd = f"echo | timeout 4 openssl s_client -connect {ip}:{port} -servername {ip} 2>/dev/null | openssl x509 -noout -subject -issuer"
        raw = subprocess.check_output(cmd, shell=True).decode().strip()
        if not raw: return None

        subject_line = ""
        issuer_line  = ""
        for line in raw.splitlines():
            ll = line.lower()
            if ll.startswith("subject="): subject_line = line
            elif ll.startswith("issuer="): issuer_line = line

        cn_match = re.search(r"CN\s*=\s*([^\s,/]+)", subject_line, re.IGNORECASE)
        cn_raw   = cn_match.group(1).strip() if cn_match else None
        cn_clean = cn_raw.lstrip("*").lstrip(".") if cn_raw else None

        return {
            "raw_subject": subject_line.replace("subject=", "").strip(),
            "raw_issuer":  issuer_line.replace("issuer=", "").strip(),
            "cn":          cn_clean,
        }
    except:
        return None

def verify_domain_live(domain: str):
    """Verifies if the extracted domain actually resolves/responds."""
    if not domain: return False, None
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L", "--max-time", "8", "--insecure", f"https://{domain}"]
        result = subprocess.check_output(cmd, timeout=12).decode().strip()
        code = int(result) if result.isdigit() else None
        return (code is not None and code > 0), code
    except:
        return False, None

# ================== REPORTERS & FALLBACKS ==================

def send_telegram(message: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or "YOUR_BOT_TOKEN" in TELEGRAM_BOT_TOKEN:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=8
        )
        return r.json().get("ok", False)
    except Exception as e:
        print(f"   [!] Telegram error: {e}")
        return False

def telegram_fallback(row_data, error_reason):
    ts, ip, url, status_label, domain = row_data
    msg = (
        f"⚠️ <b>Google Sheets Sync Failed</b>\n"
        f"<i>Reason: {error_reason}</i>\n\n"
        f"🚨 <b>Fallback Alert — Dashboard Found</b>\n"
        f"<b>Domain:</b> <code>{domain}</code>\n"
        f"<b>IP:</b> <code>{ip}</code>\n"
        f"<b>Status:</b> {status_label}\n"
        f"<b>URL:</b> {url}\n"
    )
    send_telegram(msg)

def update_google_sheets(row_data):
    if not GOOGLE_CREDS_JSON:
        telegram_fallback(row_data, "GOOGLE_SHEETS_CREDS_JSON is empty.")
        return
    try:
        scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        creds_info = json.loads(GOOGLE_CREDS_JSON)
        credentials = Credentials.from_service_account_info(creds_info, scopes=scopes)
        client = gspread.authorize(credentials)
        sheet = client.open("BountyResults").sheet1
        sheet.append_row(row_data)
        print("   [+] Synced to Google Sheets.")
    except Exception as e:
        print(f"   [!] Google Sheets Error: {e}")
        telegram_fallback(row_data, str(e))

def send_domain_alert(ip: str, result: dict) -> None:
    ssl = result["ssl_info"] or {}
    dn = result["domain_name"] or "Unknown"
    live = f"✅ Live (HTTP {result['domain_http']})" if result["domain_live"] else "⚠️ Curl failed"
    status_label = result.get("vuln_note") or result["dashboard"]
    
    # Add fire emoji if it's a critical CVE hit
    icon = "🔥 CRITICAL VULN" if "CVE" in status_label or "admin:admin" in status_label else "🚨 Exposed Dashboard"
    
    msg = (
        f"{icon}\n\n"
        f"<b>Domain    :</b> <code>{dn}</code>\n"
        f"<b>IP        :</b> <code>{ip}</code>\n"
        f"<b>Status    :</b> {status_label}\n"
        f"<b>URL       :</b> {result['url']}{result['path']}\n"
        f"<b>Domain    :</b> {live}\n\n"
        f"<b>SSL Subject:</b> {ssl.get('raw_subject', '—')}"
    )
    send_telegram(msg)

# ================== SCORING & EXPLOIT CHECKS ==================

SOFT_404_SIGNALS = ["page not found", "404 not found", "error 404", "access denied", "403 forbidden"]

def is_soft_404(text: str) -> bool:
    return any(s in text.lower() for s in SOFT_404_SIGNALS)

def score_response(text: str, headers: dict, db: dict) -> bool:
    lower = text.lower()
    if any(n_kw in lower for n_kw in db.get("neg_kw", [])): return False
    
    hdr_str = " ".join(v.lower() for v in headers.values())
    if db["title_kw"]:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        title_text  = title_match.group(1).lower() if title_match else ""
        if not any(kw.lower() in title_text or kw.lower() in hdr_str for kw in db["title_kw"]):
            return False

    if not any(kw.lower() in lower for kw in db["body_kw"]): return False
    if is_soft_404(text): return False
    return True

def check_grafana_vulnerabilities(url):
    """Checks for admin:admin AND the new CVE-2026-27877 Credential Leak."""
    base_url = url.split('/login')[0].rstrip('/')
    results = []

    try:
        r = requests.get(f"{base_url}/api/admin/stats", auth=('admin', 'admin'), timeout=5, verify=False)
        if r.status_code == 200 and "dashboards" in r.text:
            results.append("🚨 CRITICAL: admin:admin works")
    except: pass

    try:
        r_cve = requests.get(f"{base_url}/api/public-dashboards", timeout=5, verify=False)
        if r_cve.status_code == 200:
            if '"secureJsonData"' in r_cve.text or '"password"' in r_cve.text:
                 results.append("🔥 EXPLOIT: CVE-2026-27877 Credential Leak detected!")
            else:
                 results.append("🔓 OPEN: Public Dashboards Enabled")
    except: pass

    return " | ".join(results) if results else None

def check_dashboard(ip: str, db: dict) -> dict | None:
    for port in db["ports"]:
        for scheme in ["http", "https"]:
            if not running: return None
            for path in db["paths"]:
                url = f"{scheme}://{ip}:{port}"
                full_url = f"{url}{path}"
                try:
                    r = requests.get(full_url, timeout=TIMEOUT, verify=False, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
                    if r.status_code not in db["ok_codes"] or len(r.text) < db["min_size"]: continue
                    if not score_response(r.text, dict(r.headers), db): continue

                    ssl_info = None
                    for ssl_port in ([443] if scheme == "http" else [port, 443]):
                        ssl_info = get_ssl_cn(ip, ssl_port)
                        if ssl_info and ssl_info.get("cn"): break
                    
                    domain_name = ssl_info["cn"] if ssl_info else None
                    domain_live, domain_http = verify_domain_live(domain_name)
                    
                    vuln_note = None
                    if db["name"] == "Grafana":
                        vuln_note = check_grafana_vulnerabilities(url)
                    
                    # Log to Google Sheets immediately
                    ts = time.strftime("%Y-%m-%d %H:%M:%S")
                    status_label = vuln_note if vuln_note else db["name"]
                    update_google_sheets([ts, ip, full_url, status_label, domain_name or "Unknown"])

                    return {
                        "url":         url,
                        "path":        path,
                        "dashboard":   db["name"],
                        "status_code": r.status_code,
                        "ssl_info":    ssl_info,
                        "domain_name": domain_name,
                        "domain_live": domain_live,
                        "domain_http": domain_http,
                        "vuln_note":   vuln_note
                    }
                except:
                    continue
    return None

# ================== MAIN EXECUTION ==================

def main():
    global running
    parser = argparse.ArgumentParser(description="Automated Bounty Dashboard Scanner")
    parser.add_argument("--tags", type=str, default="all", help=f"Comma-separated tags. Options: {', '.join(DASHBOARDS.keys())}")
    args = parser.parse_args()

    selected_tags = list(DASHBOARDS.keys()) if args.tags.lower() == "all" else [t.strip().lower() for t in args.tags.split(",")]
    invalid = [t for t in selected_tags if t not in DASHBOARDS]
    if invalid:
        print(f"[!] Unknown tags: {', '.join(invalid)}")
        return

    print(f"[*] Starting Scan | Tags: {', '.join(selected_tags)}")
    if not os.path.exists(INPUT_FILE):
        print(f"[-] {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE) as f:
        ips = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    confirmed_with_domain, confirmed_without_domain, manual = [], [], []

    try:
        for idx, ip in enumerate(ips, 1):
            if not running: break
            print(f"[{idx}/{len(ips)}] → {ip}", end="\r")
            found_any = False

            for tag in selected_tags:
                result = check_dashboard(ip, DASHBOARDS[tag])
                if result and running:
                    found_any = True
                    dn = result["domain_name"] or "—"
                    status = result.get("vuln_note") or result['dashboard']
                    print(f"\n   🎯 HIT: {status} | {result['url']}{result['path']} | domain: {dn}")

                    if result["domain_name"]:
                        confirmed_with_domain.append((ip, result))
                        send_domain_alert(ip, result)
                    else:
                        confirmed_without_domain.append((ip, result))

            if not found_any:
                manual.append(ip)
            time.sleep(0.5)

    except KeyboardInterrupt:
        pass

    # Save physical text files as backup
    with open(CONFIRMED_FILE, "w", encoding="utf-8") as f:
        for ip, res in confirmed_with_domain:
            f.write(f"IP: {ip} | Domain: {res['domain_name']} | Hit: {res.get('vuln_note') or res['dashboard']}\n")

    with open(NO_DOMAIN_FILE, "w", encoding="utf-8") as f:
        for ip, res in confirmed_without_domain:
            f.write(f"IP: {ip} | Hit: {res.get('vuln_note') or res['dashboard']}\n")

    print(f"\n[*] Scan Complete. Domain Hits: {len(confirmed_with_domain)} | No Domain: {len(confirmed_without_domain)}")

if __name__ == "__main__":
    main()
