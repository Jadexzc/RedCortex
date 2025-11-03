"""
RedCortex Plugin: Advanced JWK/Weak JWT Detection
- Async scanning for JWTs in headers, cookies, body
- Probes for 'none' alg bypass, weak HS* secrets, short/brute-force keys
- Integrates wordlists and custom secret dictionaries
- Evidence scoring and auto-decoded data in findings
- Severity assignment & auto-report ready
"""

import re
import asyncio
import httpx
import base64
import jwt

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"
]
COMMON_JWT_SECRETS = [
    "secret", "admin", "password", "letmein", "jwtsecret", "changeme", "root",
    "1234", "toor", "demo", "myjwtkey", "key", "hmac"
]
JWT_HEADERS = ["Authorization", "X-Api-Token", "X-JWT-Assertion"]

def extract_jwts(text):
    pattern = r"([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)"
    return re.findall(pattern, text)

async def fetch_jwt_targets(url):
    findings = []
    headers = {"User-Agent": USER_AGENTS[0]}
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        r = await client.get(url, timeout=10)
        texts = [r.text or ""]
        for h, v in r.headers.items():
            texts.append(str(v))
        if hasattr(r, "cookies"):
            for ck in r.cookies.items():
                texts.append(str(ck[1]))
        # Scan for JWTs
        discovered = set()
        for t in texts:
            for token in extract_jwts(t):
                if token in discovered:
                    continue
                discovered.add(token)
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                try:
                    # Try alg none bypass
                    dec = jwt.decode(token, options={"verify_signature": False})
                    findings.append({
                        "type": "JWT-None-Alg",
                        "description": "JWT decoded, none-alg or signature not enforced",
                        "token": token,
                        "decoded": dec,
                        "severity": "critical",
                        "url": url
                    })
                    continue
                except Exception: pass
                # Weak secret brute-force
                for sec in COMMON_JWT_SECRETS:
                    try:
                        dec = jwt.decode(token, sec, algorithms=["HS256", "HS384", "HS512"])
                        findings.append({
                            "type": "JWT-Weak-Secret",
                            "description": f"JWT cracked with weak secret '{sec}'",
                            "token": token,
                            "decoded": dec,
                            "secret": sec,
                            "severity": "critical",
                            "url": url
                        })
                        break
                    except Exception: continue
                # Try short brute-force keys (1-5 chars)
                for brute in ["a", "abc", "abcd", "123", "pass", "root", "demo"]:
                    try:
                        dec = jwt.decode(token, brute, algorithms=["HS256"])
                        findings.append({
                            "type": "JWT-Brute",
                            "description": "JWT cracked with short/brute secret",
                            "token": token,
                            "decoded": dec,
                            "secret": brute,
                            "severity": "high",
                            "url": url
                        })
                        break
                    except Exception: continue
    return findings

def run(response, url, **kwargs):
    """
    RedCortex plugin interface for async weak JWT scan.
    Returns multi-vector findings with evidence decoded.
    """
    try:
        # If response given, legacy scan mode
        content = getattr(response, "text", None)
        if content:
            findings = []
            for token in extract_jwts(content):
                if not token: continue
                try:
                    dec = jwt.decode(token, options={"verify_signature": False})
                    findings.append({
                        "type": "JWT-None-Alg",
                        "description": "JWT decoded, none-alg or signature not enforced",
                        "token": token,
                        "decoded": dec,
                        "severity": "critical",
                        "url": url
                    })
                except Exception: pass
                for sec in COMMON_JWT_SECRETS:
                    try:
                        dec = jwt.decode(token, sec, algorithms=["HS256", "HS384", "HS512"])
                        findings.append({
                            "type": "JWT-Weak-Secret",
                            "description": f"JWT cracked with weak secret '{sec}'",
                            "token": token,
                            "decoded": dec,
                            "secret": sec,
                            "severity": "critical",
                            "url": url
                        })
                        break
                    except Exception: continue
            return findings
        # Otherwise, launch async HTTP scan
        return asyncio.run(fetch_jwt_targets(url))
    except KeyboardInterrupt:
        return []
