# RedCortex

RedCortex is a modern, fully automated red team web pentest and exploit framework integrating endpoint brute-forcing (dirsearch), dynamic browser-based crawling (Playwright), advanced parameter fuzzing, and a robust plugin/exploit chain engine. Supports SQLi, XSS, LFI, SSRF, IDOR, auto-chaining, credential extraction, privilege escalation, interactive shell, live dashboard, Telegram alerts, and session/attack path saving.

## Features

- **Endpoint Discovery**: Automated using both dirsearch and headless browser crawling
- **Wide Parameter Brute**: HTML/form and SecLists-based parameter discovery and testing
- **Vulnerability Plugins**: Advanced SQLi (multiple vectors), XSS, LFI, SSRF, IDOR detection—in one pass
- **Exploit Chaining**: Automatic SQLi → OS-shell, LFI config parsing/creds, IDOR brute-forcing/pivot
- **Evidence & Credential Extraction**: LFI configs auto-parsed for secrets/DB creds
- **Real-Time Reporting**: Results and chains sent to Telegram and Flask dashboard
- **Session Management**: Auto-saving scan/attack state, resumable
- **Attack Path Map**: Text-based summary of all chains found (optionally extend to visual)
- **Interactive Exploit Shell**: Post-finding playground for manual/auto-exploit
- **Robust Error Handling** and optional stealth evasion features

## Quick Start

### Clone the repo:

```bash
git clone https://github.com/youruser/goldmine-advanced.git
cd goldmine-advanced
```

### Install dependencies:

```bash
pip install -r requirements.txt
playwright install
```

**If pip fails, use pipx:**

```bash
pipx install flask
pipx install playwright
pipx install requests
pipx install beautifulsoup4
```

**Or inside a virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install
```

### Configure Telegram integration:

1. Obtain a Telegram bot token ([BotFather guide](https://core.telegram.org/bots#botfather))
2. Send `/start` or `/getid` to your bot to get your chat ID
3. Edit the Python script to set your `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` at the top.

### Run the tool:

```bash
python3 goldmine_advanced.py --url http://target.site/
```

- Output at the terminal, and at: `http://localhost:8088/report`
- All attack/state data auto-saves, findings sent to your Telegram

## Usage Tips

**Resuming:**
- If interrupted, relaunch with `--session yourfile.pkl` to resume.

**Session Artifacts:**
- Output/loot and parsed credentials are added to the `auto_creds` key in your session.

**Customizing:**
- Add/extend plugins, adjust chain logic, or expand reporting to new formats with minimal effort.

## Sample requirements.txt

```text
flask
playwright
requests
beautifulsoup4
```

## Legal & Security

- This tool is to be used **ONLY** for authorized penetration testing and red team operations.
- You must have **explicit written permission** to test any targets with this tool.

## Credits

- **Author**: [Jadenxzc]
- **Open source components**: dirsearch, Playwright, Flask, BeautifulSoup, SecLists
