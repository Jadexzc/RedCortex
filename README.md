```text
 /$$$$$$$                  /$$  /$$$$$$                      /$$                        
| $$__  $$                | $$ /$$__  $$                    | $$                        
| $$  \ $$  /$$$$$$   /$$$$$$$| $$  \__/  /$$$$$$   /$$$$$$  /$$$$$$    /$$$$$$  /$$   /$$
| $$$$$$$/ /$$__  $$ /$$__  $$| $$       /$$__  $$ /$$__  $$|_  $$_/   /$$__  $$|  $$ /$$/
| $$__  $$| $$$$$$$$| $$  | $$| $$      | $$  \ $$| $$  \__/  | $$    | $$$$$$$$ \  $$$$/ 
| $$  \ $$| $$_____/| $$  | $$| $$    $$| $$  | $$| $$        | $$ /$$| $$_____/  >$$  $$ 
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/|  $$$$$$/| $$        |  $$$$/|  $$$$$$$ /$$/\  $$
|__/  |__/ \_______/ \_______/ \______/  \______/ |__/         \___/   \_______/|__/  \__/
```

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
