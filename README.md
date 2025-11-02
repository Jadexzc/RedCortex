# RedCortex

![GitHub Actions](https://img.shields.io/github/actions/workflow/status/Jadexzc/RedCortex/ci.yml?branch=main&style=flat-square&logo=github)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/github/license/Jadexzc/RedCortex?style=flat-square)
![Documentation](https://img.shields.io/badge/docs-wiki-brightgreen?style=flat-square)
![Version](https://img.shields.io/github/v/release/Jadexzc/RedCortex?style=flat-square)

## Overview
RedCortex is an enterprise-grade automated penetration testing framework designed for red team operations and security research. Built on a modular architecture, it combines multiple reconnaissance vectors with advanced vulnerability detection and exploit chaining capabilities. The framework integrates industry-standard tools (dirsearch, Playwright) with proprietary detection engines to deliver comprehensive web application security assessments.

### Design Philosophy
RedCortex follows a chain-based exploitation methodology, enabling automatic escalation from initial vulnerability discovery to credential extraction and privilege escalation. The framework emphasizes reproducibility, evidence collection, and real-time reporting—critical requirements for professional security assessments and academic research.

---

## Architecture

> **TODO**: Add architecture diagram showing framework pipeline (Input → Discovery → Analysis → Exploitation → Reporting)

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                      RedCortex Framework                     │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface  │  Web Dashboard  │  RESTful API            │
├─────────────────────────────────────────────────────────────┤
│           Core Scanning Engine & Orchestrator               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Discovery   │  │  Analysis    │  │  Exploitation│     │
│  │  Module      │  │  Module      │  │  Module      │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────┤
│                   Plugin System (Modular)                    │
│  [SQLi] [XSS] [LFI] [SSRF] [IDOR] [Custom Plugins...]      │
├─────────────────────────────────────────────────────────────┤
│          Evidence Collection & Credential Storage           │
├─────────────────────────────────────────────────────────────┤
│  Reporting Engine  │  Telegram Alerts  │  Data Export      │
└─────────────────────────────────────────────────────────────┘
```

### Workflow Pipeline

1. **Target Input** → User specifies targets via CLI, API, or dashboard
2. **Discovery Phase** → Endpoint enumeration and parameter extraction
3. **Vulnerability Detection** → Multi-vector scanning with plugins
4. **Exploit Chaining** → Automated privilege escalation
5. **Evidence Collection** → Artifact gathering and credential extraction
6. **Reporting & Alerts** → Real-time notifications and comprehensive reports

For detailed architecture documentation, see the [Wiki Architecture Page](https://github.com/Jadexzc/RedCortex/wiki).

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

---

## Integration & Demos

### Real-time Dashboard Demo

> **TODO**: Add demo video/GIF showcasing:
> - Live scan progress monitoring
> - Real-time vulnerability discovery
> - Evidence dashboard visualization
> - Interactive findings review

**Planned Demo Content**:
- Dashboard live scan visualization
- Telegram alert flow demonstration
- API-driven scanning example
- Plugin integration showcase

### Sample Output

See [/samples](https://github.com/Jadexzc/RedCortex/tree/main/samples) directory for:
- Example JSON scan reports
- Dashboard screenshots
- Evidence collection samples
- API response examples

### API Integration Example

```python
import requests

# Start a scan via API
response = requests.post(
    'http://localhost:5000/api/scan',
    json={
        'target': 'https://example.com',
        'modules': ['sqli', 'xss', 'lfi'],
        'options': {'rate_limit': 10, 'timeout': 30}
    },
    headers={'Authorization': 'Bearer YOUR_API_KEY'}
)

scan_id = response.json()['scan_id']
print(f"Scan started: {scan_id}")

# Monitor scan progress
status = requests.get(f'http://localhost:5000/api/scan/{scan_id}/status')
print(status.json())
```

---

## Roadmap

| Phase | Feature | Status | Target |
|-------|---------|--------|--------|
| ✅ Phase 1 | Core scanning engine | **Completed** | v1.0 |
| ✅ Phase 1 | Basic vulnerability detection (SQLi, XSS, LFI) | **Completed** | v1.0 |
| ✅ Phase 1 | Plugin system architecture | **Completed** | v1.0 |
| ✅ Phase 1 | Real-time dashboard | **Completed** | v1.0 |
| ✅ Phase 1 | Telegram notifications | **Completed** | v1.0 |
| ✅ Phase 1 | Evidence collection system | **Completed** | v1.0 |
| 🔵 Phase 2 | Two-factor authentication (2FA) | In Progress | v1.1 |
| 🔵 Phase 2 | Role-based access control (RBAC) | Planned | v1.1 |
| 🔵 Phase 2 | Advanced exploit chaining | Planned | v1.1 |
| 🔵 Phase 2 | Machine learning vulnerability detection | Planned | v1.2 |
| ⚪ Phase 3 | Cloud platform scanners (AWS/Azure/GCP) | Future | v2.0 |
| ⚪ Phase 3 | Container security (Docker/K8s) | Future | v2.0 |
| ⚪ Phase 3 | Mobile app security testing | Future | v2.0 |
| ⚪ Phase 3 | API security testing module | Future | v2.0 |

**Legend**: ✅ Completed | 🔵 In Progress/Planned | ⚪ Future

For detailed roadmap and feature requests, see [GitHub Issues](https://github.com/Jadexzc/RedCortex/issues) and [Discussions](https://github.com/Jadexzc/RedCortex/discussions).

---

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Jadexzc/RedCortex.git
cd RedCortex

# Install dependencies
pip install -r requirements.txt

# Run a basic scan
python main.py --target https://example.com --scan-type basic
```

### Docker Installation (Optional)

```bash
docker build -t redcortex .
docker run -p 5000:5000 redcortex
```

---

## Usage

For comprehensive usage guides, see the [Wiki Usage Guides](https://github.com/Jadexzc/RedCortex/wiki/Usage-Guides).

### Basic Scanning

```bash
python main.py --target URL --scan-type [basic|full|stealth]
```

### Module Selection

```bash
python main.py --target URL --modules sqli,xss,lfi,ssrf,idor
```

### Advanced Options

```bash
python main.py \
  --target https://example.com \
  --modules sqli,xss \
  --rate-limit 10 \
  --output report.json \
  --chain-exploits
```

---

## Documentation

- 📚 [Wiki Home](https://github.com/Jadexzc/RedCortex/wiki) - Comprehensive documentation
- 🛠️ [Usage Guides](https://github.com/Jadexzc/RedCortex/wiki/Usage-Guides) - Detailed scanning options and workflows
- 🔌 [Plugin Development](https://github.com/Jadexzc/RedCortex/wiki/Plugin-Development) - Create custom modules
- 📊 [Scan Result Interpretation](https://github.com/Jadexzc/RedCortex/wiki/Scan-Result-Interpretation) - Understanding findings
- 🛡️ [Security Policy](SECURITY.md) - Vulnerability disclosure guidelines
- 🤝 [Contributing](CONTRIBUTING.md) - Contribution guidelines and standards
- 📝 [Changelog](CHANGELOG.md) - Version history and updates

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code of Conduct
- Development setup
- Coding standards
- Testing requirements
- Pull request process

---

## Security

**Found a vulnerability?** Please report it responsibly via our [Security Policy](SECURITY.md).

- Do NOT open public issues for security vulnerabilities
- Email: security@redcortex-project.org
- Or use [GitHub Security Advisory](https://github.com/Jadexzc/RedCortex/security/advisories/new)

---

## License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

---

## Citation

If you use RedCortex in your research, please cite:

```bibtex
@software{redcortex2025,
  author = {Jadexzc},
  title = {RedCortex: Modular Penetration Testing Framework},
  year = {2025},
  url = {https://github.com/Jadexzc/RedCortex},
  version = {1.0.0}
}
```

---

## Acknowledgments

- Built with [Playwright](https://playwright.dev/) for headless browser automation
- Integrates [dirsearch](https://github.com/maurosoria/dirsearch) for directory enumeration
- Uses [SecLists](https://github.com/danielmiessler/SecLists) for payload generation
- Inspired by industry-leading penetration testing frameworks

---

## Support

- 🐛 [Report Bugs](https://github.com/Jadexzc/RedCortex/issues/new?template=bug_report.md)
- ✨ [Request Features](https://github.com/Jadexzc/RedCortex/issues/new?template=feature_request.md)
- 💬 [Join Discussions](https://github.com/Jadexzc/RedCortex/discussions)
- 📧 Contact: [Maintainer](https://github.com/Jadexzc)

---

**⚠️ Disclaimer**: RedCortex is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any target systems. Unauthorized access to computer systems is illegal.

---

**Made with ❤️ for the security research community**
