# RedCortex

![GitHub Actions](https://img.shields.io/github/actions/workflow/status/Jadexzc/RedCortex/ci.yml?branch=main&style=flat-square&logo=github) ![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python) ![License](https://img.shields.io/github/license/Jadexzc/RedCortex?style=flat-square) ![Documentation](https://img.shields.io/badge/docs-wiki-brightgreen?style=flat-square) ![Version](https://img.shields.io/github/v/release/Jadexzc/RedCortex?style=flat-square)

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

## Installation

### Standard Installation

```bash
git clone https://github.com/Jadexzc/RedCortex.git
cd RedCortex
pip install -r requirements.txt
```

### Virtual Environment Installation (Recommended)

```bash
git clone https://github.com/Jadexzc/RedCortex.git
cd RedCortex

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Command-Line Interface

RedCortex uses a subcommand structure similar to `git` and `docker`.

#### Scan Command

Perform a security scan:

```bash
python redcortex.py scan -u <target_url> [options]
```

**Options:**

- `-u, --url`: Target URL to scan (required)
- `-v, --verbose`: Enable verbose output (can be repeated: `-v`, `-vv`, `-vvv`)
- `-t, --threads`: Number of threads for concurrent scanning (default: 10)
- `-o, --output`: Output file path (JSON format)
- `-l, --log-file`: Log file path
- `--scan-id`: Custom scan ID (default: auto-generated)

**Examples:**

```bash
# Basic scan
python redcortex.py scan -u https://example.com

# Scan with verbose output and custom threads
python redcortex.py scan -u https://example.com -vv -t 20

# Scan with output file
python redcortex.py scan -u https://example.com -o results.json

# Full options
python redcortex.py scan -u https://example.com -vvv -t 15 -o output.json -l scan.log --scan-id custom_scan_001
```

#### Report Command

Generate a report from scan results:

```bash
python redcortex.py report -i <input_file> [options]
```

**Options:**

- `-i, --input`: Input JSON file with scan results (required)
- `-o, --output`: Output report file (default: `report.txt`)
- `-f, --format`: Report format: `text`, `json`, or `html` (default: `text`)

**Examples:**

```bash
# Generate text report
python redcortex.py report -i results.json

# Generate HTML report
python redcortex.py report -i results.json -o report.html -f html

# Generate JSON report
python redcortex.py report -i results.json -o report.json -f json
```

#### Dashboard Command

Launch the web dashboard:

```bash
python redcortex.py dashboard [options]
```

**Options:**

- `-p, --port`: Port number (default: 5000)
- `-r, --results-dir`: Directory containing scan results (default: `results/`)
- `--host`: Host to bind the dashboard (default: 127.0.0.1)
- `--debug`: Enable Flask debug mode

**Examples:**

```bash
# Launch dashboard on default port
python redcortex.py dashboard

# Launch on custom port
python redcortex.py dashboard -p 8080

# Launch with custom results directory
python redcortex.py dashboard -r /path/to/results

# Launch with debug mode
python redcortex.py dashboard --debug
```

Once running, access the dashboard at `http://127.0.0.1:5000` (or your configured host/port).

**Dashboard Features:**

- **Scan List**: View all completed scans with metadata
- **Scan Details**: Inspect individual scan results, findings, and statistics
- **Filtering**: Filter findings by severity, plugin, or status
- **Export**: Download results in JSON or HTML format
- **Real-time Updates**: Auto-refresh for ongoing scans

#### Interactive Exploit Shell

Launch the interactive exploitation framework:

```bash
python redcortex.py exploit -u <target_url> [options]
```

**Options:**

- `-u, --url`: Target URL for exploitation
- `-t, --type`: Attack type (`sqli`, `xss`, `rce`, `lfi`, `custom`)
- `--payload`: Custom payload (for custom attack types)
- `--chain`: Enable attack chaining mode
- `-v, --verbose`: Enable verbose output

**Examples:**

```bash
# Launch exploit shell
python redcortex.py exploit -u https://example.com/app

# SQL injection exploitation
python redcortex.py exploit -u https://example.com/login -t sqli

# Custom payload
python redcortex.py exploit -u https://example.com/api -t custom --payload "' OR 1=1--"

# Attack chaining
python redcortex.py exploit -u https://example.com -t xss --chain
```

**Interactive Shell Commands:**

- `help`: Show available commands
- `set <param> <value>`: Set exploit parameters
- `show options`: Display current configuration
- `run`: Execute the exploit
- `chain <attack_type>`: Add attack to chain
- `execute_chain`: Run all chained attacks
- `clear`: Clear attack chain
- `exit`: Exit the shell

### Plugin System

RedCortex uses a dynamic plugin architecture. Place custom plugins in the `plugins/` directory.

#### Plugin Structure

```python
# plugins/my_custom_plugin.py

class MyCustomPlugin:
    name = "My Custom Check"
    severity = "medium"
    description = "Checks for custom vulnerability"
    
    def check(self, url, session):
        """
        Perform security check
        
        Args:
            url: Target endpoint URL
            session: requests.Session object
            
        Returns:
            dict: {
                'vulnerable': bool,
                'details': str,
                'evidence': dict (optional)
            }
        """
        try:
            response = session.get(url)
            # Perform checks
            if 'vulnerable_pattern' in response.text:
                return {
                    'vulnerable': True,
                    'details': 'Found vulnerable pattern',
                    'evidence': {'response': response.text[:500]}
                }
        except Exception as e:
            return {'vulnerable': False, 'details': str(e)}
        
        return {'vulnerable': False, 'details': 'No issues found'}
```

#### Available Plugins

- `sql_injection.py`: Detects SQL injection vulnerabilities
- `xss.py`: Identifies Cross-Site Scripting vectors
- `path_traversal.py`: Checks for directory traversal
- `command_injection.py`: Tests for OS command injection
- `xxe.py`: XML External Entity injection detection
- `open_redirect.py`: Finds open redirect vulnerabilities
- `security_headers.py`: Validates security headers

## Project Structure

```
RedCortex/
├── redcortex.py          # Main CLI entry point
├── modules/
│   ├── config.py         # Configuration management
│   ├── discovery.py      # Endpoint discovery
│   ├── plugins.py        # Plugin loader
│   ├── result.py         # Result handling and persistence
│   └── dashboard.py      # Flask dashboard application
├── plugins/              # Security check plugins
│   ├── sql_injection.py
│   ├── xss.py
│   ├── path_traversal.py
│   └── ...
├── templates/            # Dashboard HTML templates
│   ├── index.html
│   ├── scan_detail.html
│   └── ...
├── results/              # Scan results storage
├── requirements.txt      # Python dependencies
└── README.md
```

## Typical Workflow

1. **Scan a target**:
   ```bash
   python redcortex.py scan -u https://target.com -vv -o results.json
   ```

2. **Review results via dashboard**:
   ```bash
   python redcortex.py dashboard -p 8080
   ```
   Open `http://127.0.0.1:8080` in your browser

3. **Generate a detailed report**:
   ```bash
   python redcortex.py report -i results.json -o report.html -f html
   ```

4. **Exploit confirmed vulnerabilities**:
   ```bash
   python redcortex.py exploit -u https://target.com/vuln_endpoint -t sqli
   ```

5. **Chain multiple attacks**:
   ```bash
   python redcortex.py exploit -u https://target.com --chain
   # In the shell:
   # > chain xss
   # > chain sqli
   # > execute_chain
   ```

## Configuration

RedCortex can be configured through:

1. **Command-line arguments** (highest priority)
2. **Environment variables** (prefix: `REDCORTEX_`)
3. **Configuration file** (`config.json`)

Example `config.json`:

```json
{
  "default_threads": 10,
  "timeout": 30,
  "user_agent": "RedCortex/1.0",
  "max_retries": 3,
  "results_dir": "results/",
  "log_level": "INFO",
  "plugins_dir": "plugins/"
}
```

## Logging

Logging verbosity can be controlled with the `-v` flag:

- No flag: `WARNING` level (minimal output)
- `-v`: `INFO` level (standard output)
- `-vv`: `DEBUG` level (detailed output)
- `-vvv`: `DEBUG` with request/response details

Logs can be written to a file using `--log-file`:

```bash
python redcortex.py scan -u https://example.com -vv --log-file scan.log
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure virtual environment is activated
   source venv/bin/activate
   
   # Reinstall dependencies
   pip install -r requirements.txt --upgrade
   ```

2. **Plugin Not Loading**
   - Check plugin class name matches filename
   - Ensure plugin has required methods: `name`, `severity`, `description`, `check()`
   - Review logs with `-vvv` for detailed error messages

3. **Dashboard Not Starting**
   ```bash
   # Check port availability
   netstat -an | grep 5000
   
   # Use alternative port
   python redcortex.py dashboard -p 8080
   ```

4. **Scan Timeout Issues**
   ```bash
   # Reduce thread count
   python redcortex.py scan -u https://example.com -t 5
   
   # Increase timeout in config.json
   {"timeout": 60}
   ```

## Security Considerations

⚠️ **Warning**: RedCortex is designed for authorized security testing only. Unauthorized scanning may be illegal in your jurisdiction.

- Always obtain written permission before scanning
- Use responsibly and ethically
- Be aware of rate limiting and WAF triggers
- Some plugins may cause denial of service
- Results may contain sensitive information

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP for security testing methodologies
- The Python security community
- Contributors and testers

## Contact

For questions, issues, or collaboration:

- GitHub Issues: [https://github.com/Jadexzc/RedCortex/issues](https://github.com/Jadexzc/RedCortex/issues)
- Wiki: [https://github.com/Jadexzc/RedCortex/wiki](https://github.com/Jadexzc/RedCortex/wiki)
