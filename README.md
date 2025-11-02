# RedCortex
![GitHub Actions](https://img.shields.io/github/actions/workflow/status/Jadexzc/RedCortex/ci.yml?branch=main&style=flat-square&logo=github)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/github/license/Jadexzc/RedCortex?style=flat-square)
![Documentation](https://img.shields.io/badge/docs-wiki-brightgreen?style=flat-square)
![Version](https://img.shields.io/github/v/release/Jadexzc/RedCortex?style=flat-square)

## Overview

RedCortex is a **modular, CLI-driven web application security scanner** designed for red team operations and security research. The framework has been completely refactored to provide:

- **Modular Architecture**: Separated core functionality into independent modules (config, discovery, plugins, result, dashboard)
- **Dynamic Plugin System**: Load custom security checks from the `plugins/` directory
- **Structured Logging**: Comprehensive logging with verbosity controls and file output
- **Concurrent Scanning**: ThreadPoolExecutor-based endpoint scanning for improved performance
- **Flexible CLI**: Subcommand-based interface with comprehensive help documentation
- **Result Management**: Save, load, and generate reports from scan results
- **Web Dashboard**: Simple web interface to view and analyze scan results
- **Interactive Exploit Shell**: Advanced exploitation framework with attack chaining capabilities

---

## Quick Start

### Prerequisites

- Python 3.8+

### Installation

**Recommended Installation (for Kali, externally managed Python):**

```bash
python3 -m venv ~/redcortex-venv
source ~/redcortex-venv/bin/activate
pip install -r requirements.txt
```

- This sets up a virtual environment for RedCortex, avoiding system package conflicts and following best practices for Kali Linux and other secure systems.
- All CLI commands should be run from inside your activated venv for full compatibility.

**Standard Installation:**

```bash
# Clone the repository
git clone https://github.com/Jadexzc/RedCortex.git
cd RedCortex

# Install dependencies (if not using venv)
pip install -r requirements.txt
```

### Troubleshooting

- If you encounter `Externally managed environment` (PEP 668) or package install errors, DO NOT use `sudo pip` or `pipx` for library installs—always use a venv.
- If you run into missing package errors (e.g., requests_toolbelt), activate your venv and rerun `pip install -r requirements.txt`.

### Basic Scan

Run a basic scan against a target URL:

```bash
python RedCortex.py scan https://example.com
```

### Scan with Custom Options

```bash
python RedCortex.py scan https://example.com \
  --depth 3 \
  --threads 10 \
  --plugins xss,sqli,lfi \
  --output results.json
```

---

## CLI Commands

RedCortex provides several subcommands for different operations:

### Scan Command

Perform security scans with various options:

```bash
python RedCortex.py scan <url> [options]
```

**Options:**
- `--depth`: Maximum crawl depth (default: 2)
- `--threads`: Number of concurrent threads (default: 5)
- `--plugins`: Comma-separated list of plugins to use
- `--exclude-plugins`: Plugins to exclude
- `--output`: Save results to JSON file
- `--verbose`: Enable verbose logging
- `--log-file`: Save logs to file

**Examples:**

```bash
# Scan with specific depth and threads
python RedCortex.py scan https://example.com --depth 3 --threads 10

# Scan with specific plugins
python RedCortex.py scan https://example.com --plugins xss,sqli

# Scan and save results
python RedCortex.py scan https://example.com --output results.json

# Verbose scan with logging
python RedCortex.py scan https://example.com --verbose --log-file scan.log
```

### Plugins Command

List available security plugins:

```bash
python RedCortex.py plugins
```

**Available Plugins:**
- `xss` - Cross-Site Scripting detection
- `sqli` - SQL Injection detection
- `lfi` - Local File Inclusion detection
- `rce` - Remote Code Execution detection
- `ssrf` - Server-Side Request Forgery detection
- `open_redirect` - Open Redirect detection
- `xxe` - XML External Entity detection
- `cors` - CORS misconfiguration detection
- `jwt_weak` - JWT weak secret detection

### Report Command

Generate reports from saved scan results:

```bash
python RedCortex.py report <result_file> [--format <format>]
```

**Formats:**
- `console` - Display in terminal (default)
- `html` - Generate HTML report
- `json` - Output JSON format
- `csv` - Generate CSV report

**Examples:**

```bash
# View results in console
python RedCortex.py report results.json

# Generate HTML report
python RedCortex.py report results.json --format html
```

### Dashboard Command

Start web dashboard to view and analyze results:

```bash
python RedCortex.py dashboard [--port <port>]
```

**Options:**
- `--port`: Port for web server (default: 5000)
- `--host`: Host address (default: 127.0.0.1)

**Example:**

```bash
python RedCortex.py dashboard --port 8080
```

### Exploit Command

Launch interactive exploit shell:

```bash
python RedCortex.py exploit
```

**Features:**
- Interactive command interface
- Attack chaining capabilities
- Session management
- Result analysis

---

## Architecture

### Directory Structure

```
RedCortex/
├── RedCortex.py          # Main entry point
├── core/
│   ├── config.py         # Configuration management
│   ├── discovery.py      # Web crawler and endpoint discovery
│   ├── plugins.py        # Plugin loader and manager
│   ├── result.py         # Result handling and storage
│   └── dashboard.py      # Web dashboard implementation
├── plugins/              # Security check plugins
│   ├── xss.py
│   ├── sqli.py
│   ├── lfi.py
│   └── ...
├── tests/                # Unit tests
├── requirements.txt      # Python dependencies
└── README.md
```

### Plugin System

RedCortex uses a modular plugin architecture. Each plugin:

1. Inherits from `BasePlugin` class
2. Implements `check()` method
3. Returns structured results
4. Can define custom severity levels

**Example Plugin:**

```python
from core.plugins import BasePlugin

class CustomPlugin(BasePlugin):
    name = "custom_check"
    description = "Custom security check"
    
    def check(self, url, **kwargs):
        # Implement security check logic
        results = []
        # ... perform checks ...
        return results
```

### Logging

RedCortex uses structured logging with multiple levels:

- **DEBUG**: Detailed diagnostic information
- **INFO**: General informational messages
- **WARNING**: Warning messages
- **ERROR**: Error messages
- **CRITICAL**: Critical issues

Enable verbose logging with `--verbose` flag or save logs with `--log-file`.

---

## Configuration

RedCortex can be configured via:

1. **Command-line arguments**: Override defaults for specific scans
2. **Environment variables**: Set persistent configuration
3. **Configuration files**: Use YAML/JSON config files (future feature)

### Environment Variables

- `REDCORTEX_THREADS`: Default thread count
- `REDCORTEX_DEPTH`: Default crawl depth
- `REDCORTEX_PLUGINS`: Default plugins to load

---

## Result Management

### Result Format

Scan results are saved in JSON format:

```json
{
  "scan_info": {
    "target": "https://example.com",
    "timestamp": "2025-01-01T12:00:00",
    "duration": 120.5
  },
  "endpoints": [...],
  "findings": [
    {
      "plugin": "xss",
      "severity": "high",
      "url": "https://example.com/search",
      "description": "...",
      "evidence": "..."
    }
  ]
}
```

### Loading Results

Results can be loaded for analysis:

```python
from core.result import ResultManager

manager = ResultManager()
results = manager.load_results("results.json")
```

---

## Web Dashboard

The web dashboard provides:

- **Results Overview**: Summary of findings by severity
- **Detailed Findings**: Interactive table with filtering
- **Endpoint Map**: Visual representation of discovered endpoints
- **Export Options**: Download reports in various formats

**Start Dashboard:**

```bash
python RedCortex.py dashboard
```

Access at: `http://127.0.0.1:5000`

---

## Interactive Exploit Shell

The exploit shell provides an interactive environment for:

- Analyzing scan results
- Chaining multiple attacks
- Session management
- Custom exploit development

**Launch Shell:**

```bash
python RedCortex.py exploit
```

**Commands:**

- `load <result_file>` - Load scan results
- `list` - List available exploits
- `use <exploit>` - Select exploit
- `set <param> <value>` - Set exploit parameters
- `run` - Execute exploit
- `chain` - Create attack chain
- `exit` - Exit shell

---

## Development

### Running Tests

RedCortex includes a comprehensive test suite:

```bash
# Run all tests
python -m pytest tests/

# Run with verbose output
python -m pytest tests/ -v

# Run specific test file
python tests/test_plugins.py
```

---

## Security and Legal

**IMPORTANT**: RedCortex is designed for authorized security testing only.

- Only use RedCortex against systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- The developers assume no liability for misuse of this tool
- Review and comply with all applicable laws and regulations

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Security research community
- Open source security tools that inspired this project
- Contributors and testers

---

## Support

- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/Jadexzc/RedCortex/issues)
- **Discussions**: Ask questions in [GitHub Discussions](https://github.com/Jadexzc/RedCortex/discussions)
- **Wiki**: Additional documentation in the [Wiki](https://github.com/Jadexzc/RedCortex/wiki)

---

## Disclaimer

This tool is provided "as is" without warranty of any kind. Use at your own risk. Always obtain proper authorization before testing any systems.
