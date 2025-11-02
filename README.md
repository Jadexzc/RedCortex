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

---

## Quick Start

### Prerequisites

- Python 3.8+
- pip install -r requirements.txt

### Basic Scan

Run a basic scan against a target URL:

```bash
python RedCortex.py scan https://example.com
```

### Scan with Custom Options

```bash
python RedCortex.py scan https://example.com \
  --paths custom_paths.txt \
  --workers 20 \
  --timeout 15 \
  --output report.txt \
  --verbose
```

### View Scan Results

```bash
# List all available scans
python RedCortex.py list

# Generate report from a specific scan
python RedCortex.py report <scan_id> --format markdown --output report.md

# Start web dashboard to view results
python RedCortex.py dashboard --port 8080
```

---

## Architecture

### Core Modules

```
RedCortex/
├── RedCortex.py       # Main CLI entry point with subcommands
├── config.py          # Configuration management (env vars, config files)
├── discovery.py       # Endpoint scanning with concurrent execution
├── plugins.py         # Dynamic plugin loader and manager
├── result.py          # Result storage, loading, and reporting
├── dashboard.py       # Web dashboard for result visualization
├── plugins/           # Plugin directory
│   ├── __init__.py
│   └── sensitive_data.py  # Sample plugin
└── tests/             # Unit tests
    └── test_plugins.py
```

---

## Usage

### CLI Commands

RedCortex uses a subcommand-based CLI interface:

```bash
python RedCortex.py <subcommand> [options]
```

Available subcommands:
- `scan` - Scan a target URL
- `resume` - Resume a previous scan
- `report` - Generate report from scan results
- `dashboard` - Start web dashboard
- `list` - List all available scans

Use `--help` with any subcommand for detailed documentation:

```bash
python RedCortex.py scan --help
```

### Scan Subcommand

Scan a target URL for security vulnerabilities:

```bash
python RedCortex.py scan TARGET_URL [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-p, --paths FILE` | File containing paths to scan (one per line) |
| `-t, --timeout SECONDS` | Request timeout in seconds |
| `-w, --workers N` | Number of concurrent workers |
| `-o, --output FILE` | Save report to FILE |
| `--scan-id ID` | Custom scan ID (auto-generated if not provided) |
| `--plugins-dir DIR` | Directory containing plugins (default: plugins) |
| `-v, --verbose` | Enable verbose/debug logging |
| `--log-file FILE` | Write logs to FILE |
| `--config FILE` | Configuration file path |

**Examples:**

```bash
# Basic scan
python RedCortex.py scan https://example.com

# Scan with custom paths
python RedCortex.py scan https://example.com --paths paths.txt

# Verbose scan with increased concurrency
python RedCortex.py scan https://example.com --verbose --workers 30

# Save scan with custom ID and output
python RedCortex.py scan https://example.com --scan-id my_scan --output results.txt
```

### Report Subcommand

Generate a report from scan results:

```bash
python RedCortex.py report SCAN_ID [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --format FORMAT` | Report format: `text` or `markdown` (default: text) |
| `-o, --output FILE` | Save report to FILE (prints to stdout if not specified) |

**Examples:**

```bash
# Generate text report to stdout
python RedCortex.py report 20241103_123456

# Generate markdown report to file
python RedCortex.py report 20241103_123456 --format markdown --output report.md
```

### Dashboard Subcommand

Start a web dashboard to view scan results:

```bash
python RedCortex.py dashboard [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-p, --port PORT` | Dashboard port (default: 8080) |

**Example:**

```bash
python RedCortex.py dashboard --port 8000
```

Then open http://localhost:8000 in your browser.

### List Subcommand

List all available scans:

```bash
python RedCortex.py list
```

---

## Configuration

### Configuration File

Create a `config.json` file for persistent configuration:

```json
{
  "user_agents": [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  ],
  "paths": [
    "/admin",
    "/api",
    "/.git",
    "/.env"
  ],
  "timeout": 10,
  "max_workers": 10,
  "output_dir": "results",
  "log_file": "redcortex.log",
  "dashboard_port": 8080
}
```

Use with `--config` flag:

```bash
python RedCortex.py scan https://example.com --config config.json
```

### Environment Variables

Override configuration with environment variables:

```bash
export REDCORTEX_TIMEOUT=15
export REDCORTEX_MAX_WORKERS=20
export REDCORTEX_OUTPUT_DIR=/path/to/results
export REDCORTEX_LOG_FILE=/path/to/redcortex.log
export REDCORTEX_DASHBOARD_PORT=9000
```

---

## Plugin Development

### Creating a Plugin

Plugins are Python modules placed in the `plugins/` directory. Each plugin must implement a `run(response, url)` function:

```python
"""Example plugin for detecting XSS vulnerabilities."""

def run(response, url):
    """
    Check for XSS vulnerabilities.
    
    Args:
        response: HTTP response object
        url: URL that was scanned
        
    Returns:
        List of findings (empty list if none found)
    """
    findings = []
    
    # Plugin logic here
    if "<script>" in response.text:
        findings.append({
            'severity': 'HIGH',
            'description': 'Potential XSS vulnerability detected',
            'url': url
        })
    
    return findings
```

### Plugin Structure

Each finding should be a dictionary with:

- `severity`: String ('HIGH', 'MEDIUM', or 'LOW')
- `description`: String describing the finding
- `url`: The URL where the finding was discovered
- Additional optional fields as needed

### Sample Plugin

See `plugins/sensitive_data.py` for a complete example that detects:

- API keys
- Access tokens
- Email addresses
- SSN patterns
- Credit card patterns

---

## Testing

Run the test suite:

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
