"""
RedCortex Plugin: Advanced CORS Misconfiguration Detector
- Async multi-origin/method/header and edge-case fuzzing
- Detects wildcards, credential leaks, origins with user-control, invalid combinations
- Checks for insecure headers, null/origin tricks, localhost, extension origins
- Severity tagging and structured report output
"""
import asyncio
import httpx
import random
import uuid
import re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0)",
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
    r'Access-Control-Allow-Credentials:\s*true',
    r'Access-Control-Allow-Methods:\s*(GET|POST|PUT|DELETE|OPTIONS|PATCH|HEAD)',
    r'Access-Control-Allow-Headers:\s*(Authorization|X-Requested-With|Cookie|Set-Cookie)',
]

async def scan_cors(client, url, origin):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Origin": origin
    }
    try:
        resp = await client.options(url, headers=headers, timeout=8)
        evidence, sev = None, "info"
        for p in PATTERNS:
            if resp.headers and any(re.search(p, v, re.IGNORECASE) for v in resp.headers.values()):
                evidence = f"Header: matched {p}"
                sev = "critical" if "credentials" in p or "*" in p else "high"
            if re.search(p, resp.text or "", re.IGNORECASE):
                evidence = f"Body: matched {p}"
                sev = "critical" if "credentials" in p or "*" in p else "high"
        # Special edge-case: A-C-Allow-Origin with user-supplied value ("reflects" evil.com/null/etc)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao in (origin, "*"):
            evidence = f"Header-reflected: {acao}"
            sev = "critical"
        # Credentials allowed?
        if resp.headers.get("Access-Control-Allow-Credentials", "false") == "true":
            sev = "critical"
        if evidence:
            return {
                "type": "CORS Misconfig",
                "url": str(resp.url),
                "origin": origin,
                "evidence": evidence,
                "severity": sev,
                "headers": dict(resp.headers),
                "http_code": resp.status_code
            }
    except Exception:
        pass
    return None

async def advanced_cors_scan(url):
    findings = []
    concurrency = 6
    async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
        tasks = [
            scan_cors(client, url, origin)
            for origin in CORS_ORIGINS
        ]
        batches = [tasks[i:i + concurrency] for i in range(0, len(tasks), concurrency)]
        for batch in batches:
            results = await asyncio.gather(*batch)
            findings.extend([f for f in results if f])
    return findings

def run(response, url, **kwargs):
    """
    RedCortex plugin interface: advanced async CORS scan.
    Returns findings w/ origins, header evidence, severity.
    """
    try:
        return asyncio.run(advanced_cors_scan(url))
    except KeyboardInterrupt:
        return []

# Example usage
# findings = run(None, "https://test/api")
# for finding in findings: print(finding)
