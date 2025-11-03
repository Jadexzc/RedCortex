"""
RedCortex Plugin: Advanced Sensitive Data Exposure Detector
- Async multi-endpoint/param scanning
- Advanced regex AND Shannon entropy/length for key/secret detection
- Context-aware parsing (headers, body, in JS, in comments, JSON, URLs)
- Finds API keys, JWTs, tokens, secrets, creds, emails, SSNs, credit cards, session IDs, internal endpoints
- Severity scoring for risk management
- HTML/JSON/report API ready
"""

import re
import httpx
import asyncio
import math
import json

SENSITIVE_PATTERNS = [
    # Keys and Secrets
    (r'(["\'`]?aws[^"\':=]{0,20}_key["\'`]?\s*[:=]\s*["\'][A-Za-z0-9/+=]{20,40}["\'])', 'AWS Key', 'HIGH'),
    (r'(["\'`]?access[_-]?token["\'`]?\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,80}["\'])', 'Access Token', 'HIGH'),
    (r'(["\'`]?api[_-]?key["\'`]?\s*[:=]\s*["\'][A-Za-z0-9\-_]{20,60}["\'])', 'API Key', 'HIGH'),
    (r'(secret[_-]?key\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,80}["\'])', 'Secret Key', 'HIGH'),
    (r'(["\']eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}["\'])', 'JWT Token', 'HIGH'),
    # Credentials
    (r'(password\s*[:=]\s*[\'"][^\'"\n]{6,64}[\'"])', 'Password', 'HIGH'),
    (r'(sessionid\s*=\s*[A-Za-z0-9]{20,})', 'SessionID', 'HIGH'),
    # Emails, SSNs, CCs
    (r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', 'Email', 'MEDIUM'),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN Pattern', 'HIGH'),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', 'Credit Card', 'HIGH'),
    # Private URLs
    (r'https?://(?:internal|dev|staging|test)[^\s"\']+', 'Internal URL', 'LOW'),
    # File/system hints
    (r'(/[a-zA-Z0-9_\-]{0,40}/(config|secrets|pass|private|key)[^\'"\s]{0,60})', 'Sensitive Path', 'MEDIUM'),
]

def shannon_entropy(data):
    if not data or len(data) < 8:
        return 0.
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

async def scan_sensitive(url):
    findings = []
    headers = {"User-Agent": "Sensitive/RedCortex"}
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(url, timeout=15)
            text = r.text or ""
            # Search in headers, too
            all_targets = [text]
            if hasattr(r, "headers"):
                for h, v in r.headers.items():
                    if v and isinstance(v, str):
                        all_targets.append(f"{h}: {v}")
            for content in all_targets:
                for pattern, desc, sev in SENSITIVE_PATTERNS:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        evidence = match.group(0)
                        # Extra: filter false positives with entropy/length if a "secret"/"token"
                        if desc in {"API Key", "Access Token", "Secret Key"}:
                            entropy = shannon_entropy(evidence)
                            if entropy < 3.0:
                                continue
                        findings.append({
                            "type": desc,
                            "url": url,
                            "severity": sev,
                            "evidence": evidence,
                            "location": "header" if content != text else "body"
                        })
            # Extra: find any very high-entropy suspicious strings
            for s in re.findall(r'["\']([A-Za-z0-9/+]{24,})["\']', text):
                if shannon_entropy(s) > 4:
                    findings.append({
                        "type": "High-Entropy String (possible secret)",
                        "url": url,
                        "severity": "HIGH",
                        "evidence": s,
                        "location": "body"
                    })
        except Exception as e:
            pass
        return findings

def run(response, url, **kwargs):
    """
    RedCortex plugin interface for async sensitive data scan.
    Returns ultra-detailed occurrences and entropy-filtered secrets.
    """
    try:
        # If response is provided, use legacy single-shot mode
        content = getattr(response, "text", None)
        if content:
            findings = []
            for pattern, desc, sev in SENSITIVE_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    evidence = match.group(0)
                    if desc in {"API Key", "Access Token", "Secret Key"}:
                        if shannon_entropy(evidence) < 3.0:
                            continue
                    findings.append({
                        "type": desc,
                        "url": url,
                        "severity": sev,
                        "evidence": evidence,
                        "location": "body"
                    })
            for s in re.findall(r'["\']([A-Za-z0-9/+]{24,})["\']', content):
                if shannon_entropy(s) > 4:
                    findings.append({
                        "type": "High-Entropy String (possible secret)",
                        "url": url,
                        "severity": "HIGH",
                        "evidence": s,
                        "location": "body"
                    })
            return findings
        # Else: launch async for given url!
        return asyncio.run(scan_sensitive(url))
    except KeyboardInterrupt:
        return []
