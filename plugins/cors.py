"""
RedCortex Plugin: Advanced CORS Misconfiguration Detection

Tests origins, methods, headers for policy bypass, wildcard, and credential leak.
"""

import requests, random, uuid

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)"
]

CORS_ORIGINS = [
    "https://evil.com",
    "null",
    "https://sub.evil.com",
    f"https://{uuid.uuid4().hex}.evil.com",
    "http://localhost",
    "http://127.0.0.1",
    "chrome-extension://abc"
]

CORS_HEADERS = [
    {},
    {"Access-Control-Request-Method": "GET"},
    {"Access-Control-Request-Method": "POST"},
    {"Access-Control-Request-Headers": "Authorization, X-Requested-With"},
    {"Origin": "https://evil.com"}
]

PATTERNS = [
    r"Access-Control-Allow-Origin:\s*\*", 
    r'Access-Control-Allow-Origin:\s*https://evil\.com',
    r'Access-Control-Allow-Credentials:\s*true'
]

def send_req(url, headers):
    headers = {**{"User-Agent": random.choice(USER_AGENTS)}, **headers}
    try:
        resp = requests.options(url, headers=headers, timeout=8)
        return resp.status_code, resp.headers
    except Exception as e:
        return None, {}

def run(response, url):
    findings = []
    try:
        for test_origin in CORS_ORIGINS:
            for extra_headers in CORS_HEADERS:
                headers = {"Origin": test_origin, **extra_headers}
                print(f"[*] CORS: Testing Origin '{test_origin}' with headers {extra_headers}")
                sc, resp_headers = send_req(url, headers)
                if sc and resp_headers:
                    # Check for misconfig evidence
                    for patt in PATTERNS:
                        for k, v in resp_headers.items():
                            if re.search(patt, f"{k}: {v}", re.IGNORECASE):
                                findings.append({
                                    "type": "CORS",
                                    "description": f"CORS misconfig: Origin '{test_origin}', headers '{extra_headers}'",
                                    "origin": test_origin,
                                    "headers": extra_headers,
                                    "leak_header": f"{k}: {v}",
                                    "severity": "critical" if "Credentials" in k else "high",
                                    "url": url
                                })
                                return findings
    except KeyboardInterrupt:
        print("[!] Scan interrupted by user.")
        return findings
    return findings
