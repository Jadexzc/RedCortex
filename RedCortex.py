#!/usr/bin/env python3
"""RedCortex - Modular Red Team Web Pentest Framework.
Refactored version with improved modularity, logging, and CLI interface.
"""
import argparse
import logging
import sys
import os
from pathlib import Path

# Import core modules
from config import Config
from discovery import EndpointScanner
from plugins import PluginManager
from result import ResultManager
from dashboard import Dashboard


def setup_logging(verbose: bool = False, log_file: str = None):
    """Configure structured logging.
    
    Args:
        verbose: Enable verbose/debug logging
        log_file: Path to log file (optional)
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(log_format))
    
    handlers = [console_handler]
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
    
    logging.basicConfig(level=log_level, handlers=handlers)
    
    # Suppress noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)


def load_session(session_file: str) -> dict:
    """Load session state from file.
    
    Args:
        session_file: Path to session file
        
    Returns:
        Session state dictionary
    """
    import json
    try:
        with open(session_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Session file {session_file} not found, starting fresh")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Invalid session file {session_file}, starting fresh")
        return {}


def cmd_scan(args):
    """Execute a new scan.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting scan: {args.url}")
    
    # Initialize components
    config = Config(
        target_url=args.url,
        max_threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    scanner = EndpointScanner(config)
    plugin_manager = PluginManager(config)
    result_manager = ResultManager(config.output_dir)
    
    # Run discovery
    logger.info("Running endpoint discovery...")
    endpoints = scanner.discover()
    logger.info(f"Found {len(endpoints)} endpoints")
    
    # Run plugins
    logger.info("Running security tests...")
    findings = plugin_manager.run_all(endpoints)
    
    # Save results
    scan_id = result_manager.save_results({
        'target': args.url,
        'endpoints': endpoints,
        'findings': findings,
        'timestamp': logging.Formatter().formatTime(logging.LogRecord(
            '', 0, '', 0, '', (), None))
    })
    
    logger.info(f"Scan complete! Results saved with ID: {scan_id}")
    
    # Show summary
    critical = sum(1 for f in findings if f.get('severity') == 'critical')
    high = sum(1 for f in findings if f.get('severity') == 'high')
    medium = sum(1 for f in findings if f.get('severity') == 'medium')
    low = sum(1 for f in findings if f.get('severity') == 'low')
    
    print("\n=== Scan Summary ===")
    print(f"Target: {args.url}")
    print(f"Endpoints: {len(endpoints)}")
    print(f"Findings: {len(findings)}")
    print(f"  Critical: {critical}")
    print(f"  High: {high}")
    print(f"  Medium: {medium}")
    print(f"  Low: {low}")
    print(f"\nScan ID: {scan_id}")


def cmd_resume(args):
    """Resume an existing scan.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Resuming scan: {args.scan_id}")
    
    # Load scan data
    result_manager = ResultManager()
    scan_data = result_manager.load_results(args.scan_id)
    
    if not scan_data:
        logger.error(f"Scan {args.scan_id} not found")
        sys.exit(1)
    
    # Initialize components with saved config
    config = Config(
        target_url=scan_data['target'],
        max_threads=args.threads if hasattr(args, 'threads') else 10,
        timeout=args.timeout if hasattr(args, 'timeout') else 30
    )
    
    plugin_manager = PluginManager(config)
    
    # Resume from where we left off
    remaining_endpoints = [e for e in scan_data['endpoints'] 
                          if e not in scan_data.get('scanned', [])]
    
    logger.info(f"Resuming with {len(remaining_endpoints)} remaining endpoints")
    
    # Run plugins on remaining endpoints
    new_findings = plugin_manager.run_all(remaining_endpoints)
    
    # Merge and save results
    scan_data['findings'].extend(new_findings)
    scan_data['scanned'] = scan_data.get('scanned', []) + remaining_endpoints
    result_manager.save_results(scan_data, args.scan_id)
    
    logger.info("Scan resumed and updated")


def cmd_report(args):
    """Generate a report for a scan.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    result_manager = ResultManager()
    scan_data = result_manager.load_results(args.scan_id)
    
    if not scan_data:
        logger.error(f"Scan {args.scan_id} not found")
        sys.exit(1)
    
    # Generate report
    if args.format == 'markdown':
        report = result_manager.generate_markdown_report(scan_data)
    else:
        report = result_manager.generate_text_report(scan_data)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {args.output}")
    else:
        print(report)


def cmd_dashboard(args):
    """Start the web dashboard.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    port = args.port if hasattr(args, 'port') and args.port else 8080
    
    logger.info(f"Starting dashboard on port {port}")
    dashboard = Dashboard(port=port)
    dashboard.run()


def cmd_list(args):
    """List all available scans.
    
    Args:
        args: Parsed command-line arguments
    """
    result_manager = ResultManager()
    scans = result_manager.list_scans()
    
    if not scans:
        print("No scans found")
        return
    
    print("Available scans:")
    for scan in scans:
        print(f"  {scan['id']}: {scan['target']} ({scan['timestamp']})")


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser.
    
    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description='RedCortex - Modular Red Team Web Pentest Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--log-file', metavar='FILE',
                       help='Write logs to FILE')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan subcommand
    scan_parser = subparsers.add_parser('scan', help='Start a new scan')
    scan_parser.add_argument('url', help='Target URL to scan')
    scan_parser.add_argument('-t', '--threads', type=int, default=10,
                            help='Number of concurrent threads (default: 10)')
    scan_parser.add_argument('--timeout', type=int, default=30,
                            help='Request timeout in seconds (default: 30)')
    scan_parser.add_argument('--user-agent', metavar='UA',
                            help='Custom user agent string')
    scan_parser.add_argument('-s', '--session', metavar='FILE',
                            help='Session file to save/load state')
    
    # Resume subcommand
    resume_parser = subparsers.add_parser('resume', help='Resume an existing scan')
    resume_parser.add_argument('scan_id', help='Scan ID to resume')
    resume_parser.add_argument('-t', '--threads', type=int,
                              help='Override thread count')
    resume_parser.add_argument('--timeout', type=int,
                              help='Override timeout')
    
    # Report subcommand
    report_parser = subparsers.add_parser('report', help='Generate a scan report')
    report_parser.add_argument('scan_id', help='Scan ID to generate report for')
    report_parser.add_argument('-f', '--format', choices=['text', 'markdown'],
                             default='text', help='Report format (default: text)')
    report_parser.add_argument('-o', '--output', metavar='FILE',
                             help='Save report to FILE (prints to stdout if not specified)')
    
    # Dashboard subcommand
    dashboard_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dashboard_parser.add_argument('-p', '--port', type=int, metavar='PORT',
                                help='Dashboard port (default: 8080)')
    
    # List subcommand
    list_parser = subparsers.add_parser('list', help='List all available scans')
    
    return parser


def main():
    """Main entry point for RedCortex."""
    parser = create_parser()
    args = parser.parse_args()
    state = load_session(args.session) if args.session else {}
    state.setdefault("chain", [])
    state.setdefault("results", [])
    
    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file if hasattr(args, 'log_file') else None)
    
    # Show help if no command specified
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    commands = {
        'scan': cmd_scan,
        'resume': cmd_resume,
        'report': cmd_report,
        'dashboard': cmd_dashboard,
        'list': cmd_list
    }
    
    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
