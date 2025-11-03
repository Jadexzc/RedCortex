#!/usr/bin/env python3
"""
RedCortex - Modular Red Team Web Pentest Framework (Python 3.8+)
Refactored for advanced plugin selection, logging, reporting, and user experience.

Usage:
  python RedCortex.py scan <url> [--plugins xss,sqli,lfi,...] [--output result.json]
  python RedCortex.py list
  python RedCortex.py report <scan_id> [--format json|csv|html] [--output file]
  python RedCortex.py dashboard [--port 8080]
  python RedCortex.py shell <scan_id>
  python RedCortex.py --help
  python RedCortex.py --version

Available Plugins:
  xss, sqli, lfi, rce, ssrf, cors, sensitive_data, open_redirect, xxe, jwk_weak

Examples:
  python RedCortex.py scan https://example.com --plugins xss,sqli
  python RedCortex.py report 20251103-001 --format json --output findings.json
  python RedCortex.py dashboard --port 9090
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# External packages required: colorama (for CLI colors)
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    Fore = Style = lambda x: ''
    def colorama_init(): pass

# Core modules
from config import Config
from discovery import EndpointScanner
from plugin_manager import PluginManager
from result import ResultManager
from dashboard import Dashboard
from shell import interactive_shell

def load_logo():
    logo_path = Path(__file__).parent / "plugins" / "logo" / "RedCortex.txt"
    try:
        with open(logo_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "RedCortex"

def setup_logging(verbose=False, log_file=None):
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(log_format))
    handlers = [console_handler]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
    logging.basicConfig(level=log_level, handlers=handlers)

def color_sev(sev):
    if sev.lower() in ('critical', 'high'):
        return f"{Fore.RED}{sev}{Style.RESET_ALL}"
    elif sev.lower() == 'medium':
        return f"{Fore.YELLOW}{sev}{Style.RESET_ALL}"
    elif sev.lower() == 'low':
        return f"{Fore.BLUE}{sev}{Style.RESET_ALL}"
    return sev

def main():
    print(load_logo())  

    parser = argparse.ArgumentParser(
        prog="RedCortex",
        description="RedCortex - Modular Red Team Web Pentest Framework (Python 3.8+)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Plugins: xss, sqli, lfi, rce, ssrf, cors, sensitive_data, open_redirect, xxe, jwk_weak

Examples:
  python RedCortex.py scan https://target --plugins xss,sqli
  python RedCortex.py report <scan_id> --format json --output findings.json
  python RedCortex.py dashboard --port 9090
        """
    )
    parser.add_argument('--version', action='version', version='RedCortex v1.0.0')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--log-file', help='Path to log file')
    subparsers = parser.add_subparsers(dest='subcommand', required=True, help='Subcommand to run')

    # scan command
    scan_parser = subparsers.add_parser('scan', help='Run advanced web vulnerability scan')
    scan_parser.add_argument('target_url', help='Target URL to scan')
    scan_parser.add_argument('--plugins', help='Comma-separated plugins to use (default: all)')
    scan_parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads')
    scan_parser.add_argument('--output', help='Write results to JSON file')

    # list command
    list_parser = subparsers.add_parser('list', help='List available scans')

    # report command
    report_parser = subparsers.add_parser('report', help='Generate scan report')
    report_parser.add_argument('scan_id', help='Scan session ID')
    report_parser.add_argument('--format', choices=['json', 'csv', 'html'], default='json', help='Report format')
    report_parser.add_argument('--output', help='Output file for report')

    # dashboard command
    dash_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dash_parser.add_argument('--port', type=int, default=8080, help='Dashboard port')

    # shell command
    shell_parser = subparsers.add_parser('shell', help='Launch interactive exploit shell')
    shell_parser.add_argument('scan_id', help='Scan session ID')
    shell_parser.add_argument('--session', help='Session file for command history')

    args = parser.parse_args()
    setup_logging(args.verbose, args.log_file)

    if args.subcommand == 'scan':
        logging.info(f"Starting scan on {args.target_url}")
        plugin_manager = PluginManager()
        plugins = args.plugins.split(',') if args.plugins else [p['name'] for p in plugin_manager.list_plugins()]        scanner = EndpointScanner(args.target_url, plugins, threads=args.threads)
        scan_result = scanner.run()
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                import json
                json.dump(scan_result, f, indent=2)
            print(f"{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
        # Summary output
        counts = {}
        for finding in scan_result:
            sev = finding.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        for sev, cnt in counts.items():
            print(f"{color_sev(sev)} findings: {cnt}")
        if counts.get("critical", 0): print(f"{Fore.RED}CRITICAL issues found!{Style.RESET_ALL}")

    elif args.subcommand == 'list':
        scans = ResultManager.list_scans()
        print("Available scans:", scans)

    elif args.subcommand == 'report':
        report = ResultManager.generate_report(args.scan_id, fmt=args.format)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"{Fore.GREEN}Report saved to {args.output}{Style.RESET_ALL}")
        else:
            print(report)

    elif args.subcommand == 'dashboard':
        Dashboard.run(port=args.port)

    elif args.subcommand == 'shell':
        interactive_shell(args.scan_id, session_file=args.session)

    else:
        parser.print_help()

if __name__ == "__main__":
    if sys.version_info < (3, 8):
        print("RedCortex requires Python 3.8 or newer.", file=sys.stderr)
        sys.exit(1)
    main()

