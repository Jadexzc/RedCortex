"""
RedCortex Plugin: Weak JWT Detection

Probes for 'none' alg, weak signature, common secrets, and disclosure of JWTs in headers/cookies.
"""

import requests, random, jwt, base64, re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]

COMMON_JWT_SECRETS = [
    "secret", "admin", "password", "letmein", "jwtsecret", "changeme", "root",
    "1234", "toor", "demo", "myjwtkey", "key", "hmac"
]

JWT_HEADERS = [
    "Authorization", "X-Api-Token", "X-JWT-Assertion"
]

def extract_jwt(text):
    # Searches for JWTs in response/cookie/header text
    pattern = r"([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)"
    return re.findall(pattern, text)

def send_req(url, headers=None, cookies=None):
    headers = {**{"User-Agent": random.choice(USER_AGENTS)}, **(headers or {})}
    try:
        resp = requests.get(url, headers=headers, cookies=cookies, timeout=10)
        return resp.status_code, resp.text, resp.headers, resp.cookies
    except Exception as e:
        return None, str(e), {}, {}

def run(response, url):
    findings = []
    tested = set()
    try:
        sc, body, resp_headers, resp_cookies = send_req(url)
        # Find JWTs in headers or body
        in_headers = extract_jwt(" ".join(str(v) for v in resp_headers.values()))
        in_cookies = extract_jwt(" ".join([c.value for c in resp_cookies.values()]) if resp_cookies else "")
        in_body = extract_jwt(body) if body else []
        jwt_tokens = set(in_headers + in_cookies + in_body)
        if not jwt_tokens:
            return findings
        for token in jwt_tokens:
            try:
                if token in tested:
                    continue
                tested.add(token)
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                h = base64.urlsafe_b64decode(parts[0] + "===")
                alg = "unknown"
                if b'"alg"' in h:
                    alg = str(h)
                # None alg test
                try:
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    if decoded:
                        findings.append({
                            "type": "JWT-None",
                            "description": "JWT none-alg or alg none bypass.",
                            "token": token,
                            "severity": "critical",
                            "url": url,
                            "decoded": decoded
                        })
                        continue
                except Exception: pass
                # Try common keys
                for sec in COMMON_JWT_SECRETS:
                    try:
                        decoded = jwt.decode(token, sec, algorithms=["HS256", "HS384", "HS512"])
                        findings.append({
                            "type": "JWT-WeakSecret",
                            "description": f"JWT cracked with weak secret '{sec}'",
                            "token": token,
                            "secret": sec,
                            "severity": "critical",
                            "url": url,
                            "decoded": decoded
                        })
                        break
                    except Exception:
                        continue
            except KeyboardInterrupt:
                print("[!] Scan interrupted by user.")
                return findings
    except KeyboardInterrupt:
        print("[!] Scan interrupted by user.")
        return findings
    return findings
