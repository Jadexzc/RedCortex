# RedCortex

![GitHub Actions](https://img.shields.io/github/actions/workflow/status/Jadexzc/RedCortex/ci.yml?branch=main&style=flat-square&logo=github)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/github/license/Jadexzc/RedCortex?style=flat-square)
![Documentation](https://img.shields.io/badge/docs-wiki-brightgreen?style=flat-square)
![Version](https://img.shields.io/github/v/release/Jadexzc/RedCortex?style=flat-square)

## Overview
RedCortex is a modular, CLI-driven web application security scanner for red team operations and research. It provides targeted vulnerability checks via selectable modules, threaded execution, and flexible runtime controls.

---

## Quick Start

- Install dependencies
  - Python 3.8+
  - pip install -r requirements.txt 

- Run a scan against a single URL with all modules enabled:

```bash
python RedCortex.py -u https://example.com -m all
```

- Run specific modules only (comma-separated):

```bash
python RedCortex.py --url https://example.com --modules sqli,xss
```

- Increase verbosity and threads:

```bash
python RedCortex.py -u https://example.com -m all -v -t 20
```

---

## Usage

```bash
python RedCortex.py [-u URL] [-m MODULES] [-o OUTPUT] [-v] [-t THREADS] [--timeout SECONDS] [--user-agent UA]
```

Arguments and options (from RedCortex.py):
- -u, --url URL
  - Target URL to scan (required for most runs)
- -m, --modules MODULES
  - Comma-separated list of modules to run: sqli, xss, lfi, ssrf, idor, all
- -o, --output FILE
  - Write results to specified file
- -v, --verbose
  - Enable verbose logging/output
- -t, --threads N
  - Number of worker threads (default: 10)
- --timeout SECONDS
  - HTTP request timeout (default: 30)
- --user-agent UA
  - Custom User-Agent string

Notes:
- There is no --scan-type, --rate-limit, or --chain-exploits flag in RedCortex.py.
- Use -m all to execute the full suite.

Example invocations:
```bash
# Run basic SQLi and XSS checks
python RedCortex.py -u https://target.tld -m sqli,xss

# Run everything with custom UA and timeout
python RedCortex.py -u https://target.tld -m all --user-agent "RedCortex/1.0" --timeout 45

# Save output to a file
python RedCortex.py -u https://target.tld -m all -o results.json
```

---

## Module Selection

Available modules (pass with -m/--modules):
- sqli: SQL injection probes against query params/forms
- xss: Reflected XSS payloads and indicator detection
- lfi: Local File Inclusion path traversal checks
- ssrf: Server-Side Request Forgery vector attempts
- idor: Insecure Direct Object Reference access checks
- all: Run the entire module set above

Usage patterns:
```bash
# Single module
python RedCortex.py -u https://example.com -m sqli

# Multiple modules (comma-separated)
python RedCortex.py -u https://example.com -m xss,lfi,idor

# All modules
python RedCortex.py -u https://example.com -m all
```

---

## Advanced Options

Tuning and runtime controls:
- -t, --threads
  - Controls concurrency level for checks (default: 10)
- --timeout
  - Fail slow/blocked requests faster (default: 30s)
- --user-agent
  - Identify or blend client traffic
- -v, --verbose
  - Show additional progress and diagnostic output
- -o, --output
  - Persist results to a file for later analysis

Examples:
```bash
# Higher concurrency, verbose
python RedCortex.py -u https://app.local -m all -t 32 -v

# Custom UA and shorter timeout
python RedCortex.py -u https://app.local -m sqli,xss --user-agent "Mozilla/5.0 RC" --timeout 15
```

---

## API Integration Example

If you want to invoke RedCortex from another Python script, use subprocess to call the CLI with the same arguments exposed by RedCortex.py:

```python
import subprocess

cmd = [
    "python", "RedCortex.py",
    "-u", "https://example.com",
    "-m", "sqli,xss",
    "-t", "20",
    "--timeout", "30",
    "--user-agent", "RedCortex/1.0",
    "-o", "results.json",
]

completed = subprocess.run(cmd, capture_output=True, text=True)
print(completed.stdout)
print(completed.stderr)
```

Alternatively, you can package this as a module and expose a Python API that mirrors these options—however, in the current implementation, RedCortex.py is the entrypoint and the CLI is the supported interface.

---

## Security and Legal
Use RedCortex only on targets you have explicit authorization to test. Unauthorized testing may be illegal in your jurisdiction.

---

## Found a vulnerability?
Please report it responsibly via our Security Policy (SECURITY.md).
- Do NOT open public issues for security vulnerabilities
- Email: security@redcortex-project.org
- Or use GitHub Security Advisory: https://github.com/Jadexzc/RedCortex/security/advisories/new

---

## License
This project is licensed under the MIT License (see LICENSE).

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
- Built with Playwright for headless browser automation
- Integrates dirsearch for directory enumeration
- Uses SecLists for payload generation
- Inspired by industry-leading penetration testing frameworks

---

## Support
- 🐛 Report Bugs: https://github.com/Jadexzc/RedCortex/issues/new?template=bug_report.md
- ✨ Request Features: https://github.com/Jadexzc/RedCortex/issues/new?template=feature_request.md
- 💬 Join Discussions: https://github.com/Jadexzc/RedCortex/discussions
- 📧 Contact: https://github.com/Jadexzc

---

⚠️ Disclaimer: RedCortex is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any target systems. Unauthorized access to computer systems is illegal.

—

Made with ❤️ for the security research community
