# RedCortex

## Overview

RedCortex is an enterprise-grade automated penetration testing framework designed for red team operations and security research. Built on a modular architecture, it combines multiple reconnaissance vectors with advanced vulnerability detection and exploit chaining capabilities. The framework integrates industry-standard tools (dirsearch, Playwright) with proprietary detection engines to deliver comprehensive web application security assessments.

### Design Philosophy

RedCortex follows a chain-based exploitation methodology, enabling automatic escalation from initial vulnerability discovery to credential extraction and privilege escalation. The framework emphasizes reproducibility, evidence collection, and real-time reporting—critical requirements for professional security assessments and academic research.

---

## Features

| Category | Capability | Description |
|----------|-----------|-------------|
| **Reconnaissance** | Endpoint Discovery | Multi-vector discovery using dirsearch integration and headless browser crawling (Playwright) |
| **Parameter Analysis** | Wide-Spectrum Fuzzing | HTML form extraction and SecLists-based parameter enumeration |
| **Vulnerability Detection** | Multi-Vector Scanning | SQLi (error-based, blind, time-based), XSS (reflected, stored), LFI, SSRF, IDOR detection |
| **Exploit Chaining** | Automated Escalation | SQLi-to-shell, LFI credential extraction, IDOR privilege escalation |
| **Evidence Collection** | Credential Harvesting | Automated parsing of configuration files, environment variables, and database credentials |
| **Reporting** | Multi-Channel Output | Real-time Telegram alerts, Flask-based dashboard, JSON/CSV export |
| **Session Management** | State Persistence | Resumable scans with attack path reconstruction |
| **Post-Exploitation** | Interactive Shell | Manual exploitation interface for advanced testing |
| **Evasion** | Anti-Detection | Configurable rate limiting, user-agent rotation, request randomization |

---

## System Requirements

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended for large-scale scans)
- Network access to target infrastructure
- Optional: Telegram Bot API credentials for remote alerting

---

## Installation

### Standard Installation

```bash
# Clone repository
git clone https://github.com/Jadexzc/RedCortex.git
cd RedCortex

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
playwright install chromium
```

### Alternative Installation Methods

**Using pipx (isolated environment):**

```bash
pipx install flask
pipx install playwright
pipx install requests
pipx install beautifulsoup4
playwright install chromium
```

**Docker deployment (coming soon):**

```bash
docker build -t redcortex .
docker run -p 8088:8088 redcortex --url <target>
```

---

## Configuration

### Telegram Integration (Optional)

For real-time alerting during extended assessments:

1. Create a Telegram bot via [BotFather](https://core.telegram.org/bots#botfather)
2. Obtain your bot token and chat ID (send `/start` to your bot)
3. Configure credentials in the main script:

```python
TELEGRAM_TOKEN = "your_bot_token_here"
TELEGRAM_CHAT_ID = "your_chat_id_here"
```

### Configuration File (config.json)

```json
{
  "threads": 10,
  "timeout": 30,
  "user_agent": "custom_agent",
  "stealth_mode": true,
  "rate_limit": 5,
  "session_path": "./sessions/"
}
```

---

## Usage

### Basic Scan

```bash
python3 goldmine_advanced.py --url http://target.example.com
```

### Advanced Options

```bash
# Full scan with custom wordlist
python3 goldmine_advanced.py --url http://target.example.com \
  --wordlist /path/to/custom.txt \
  --threads 20 \
  --output report.json

# Resume previous session
python3 goldmine_advanced.py --resume session_id_123

# Targeted vulnerability scan
python3 goldmine_advanced.py --url http://target.example.com \
  --modules sqli,xss,lfi \
  --stealth
```

### Workflow

1. **Discovery Phase**: Endpoint enumeration via dirsearch and Playwright crawler
2. **Parameter Mapping**: Form extraction and parameter fuzzing
3. **Vulnerability Assessment**: Multi-vector vulnerability scanning
4. **Exploitation**: Automatic exploit chaining and credential extraction
5. **Reporting**: Evidence collection and dashboard generation
6. **Post-Exploitation**: Interactive shell for manual verification

### Accessing Results

- **Terminal Output**: Real-time scan progress and findings
- **Web Dashboard**: `http://localhost:8088/report`
- **Telegram Alerts**: Instant notifications for critical findings
- **Export Formats**: JSON, CSV, XML (via dashboard)

---

## Advanced Integration

### API Endpoints

```python
# Start scan programmatically
POST /api/scan
{
  "url": "http://target.com",
  "modules": ["sqli", "xss"],
  "callback_url": "https://your-server.com/webhook"
}

# Query scan status
GET /api/status/<scan_id>

# Retrieve findings
GET /api/findings/<scan_id>
```

### CI/CD Integration

```yaml
# Example GitLab CI pipeline
security_scan:
  stage: test
  script:
    - python3 goldmine_advanced.py --url $STAGING_URL --output scan_results.json
    - test $(jq '.critical_findings' scan_results.json) -eq 0
  artifacts:
    reports:
      security: scan_results.json
```

### Custom Plugin Development

```python
# plugins/custom_vuln.py
class CustomVulnPlugin:
    def __init__(self, config):
        self.config = config
    
    def scan(self, target, params):
        # Custom vulnerability detection logic
        return findings
```

---

## Legal Notice

**IMPORTANT: AUTHORIZED USE ONLY**

RedCortex is designed exclusively for:
- Authorized penetration testing engagements
- Security research in controlled laboratory environments
- Academic study with explicit written consent
- Bug bounty programs within defined scope

**Unauthorized access to computer systems is illegal under:**
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act 1990 - United Kingdom  
- Convention on Cybercrime (Budapest Convention) - International
- Similar legislation in most jurisdictions worldwide

**Users are solely responsible for:**
1. Obtaining proper written authorization before testing
2. Complying with all applicable laws and regulations
3. Respecting scope limitations and rules of engagement
4. Handling discovered vulnerabilities responsibly

The authors and contributors assume no liability for misuse or unauthorized deployment of this framework.

---

## Citation

If you use RedCortex in your research, please cite:

```bibtex
@software{redcortex2025,
  author = {Jaden},
  title = {RedCortex: Automated Red Team Web Penetration Testing Framework},
  year = {2025},
  url = {https://github.com/Jadexzc/RedCortex},
  note = {Accessed: 2025-11-03}
}
```

---

## Architecture

```
┌─────────────────────────────────────────┐
│         RedCortex Core Engine           │
├─────────────────────────────────────────┤
│  Discovery Layer (dirsearch, Playwright)│
│  Parameter Fuzzer (SecLists)            │
│  Vulnerability Scanners (Modular)       │
│  Exploit Chain Manager                  │
│  Evidence Collector                     │
│  Session Manager                        │
└─────────────────────────────────────────┘
         ↓                ↓                ↓
   [Telegram]      [Dashboard]       [Export]
```

---

## Acknowledgments

RedCortex integrates and builds upon several open-source security tools:

- **[dirsearch](https://github.com/maurosoria/dirsearch)** - Web path scanner by Mauro Soria
- **[Playwright](https://playwright.dev/)** - Browser automation by Microsoft
- **[SecLists](https://github.com/danielmiessler/SecLists)** - Security testing wordlists by Daniel Miessler
- **[Flask](https://flask.palletsprojects.com/)** - Web framework by Pallets

Special thanks to the open-source security community for continuous research and tool development.

---

## Roadmap

- [ ] Docker containerization
- [ ] GraphQL vulnerability scanning
- [ ] API security testing module
- [ ] WebSocket exploitation
- [ ] Machine learning-based anomaly detection
- [ ] Visual attack graph generation
- [ ] Multi-target orchestration
- [ ] Cloud infrastructure enumeration (AWS, Azure, GCP)

---

## Contributing

Contributions are welcome from the security research community. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Implement changes with comprehensive testing
4. Submit a pull request with detailed documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for code standards and testing requirements.

---

## License

See [LICENSE](LICENSE) file for terms and conditions.

---

## Author

**Jaden** - [GitHub Profile](https://github.com/Jadexzc)

For professional inquiries, security disclosures, or research collaboration, please open an issue or contact via GitHub.

---

## Disclaimer

This tool is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any damage or legal consequences arising from the use or misuse of this software. Always obtain explicit written permission before conducting security assessments.
