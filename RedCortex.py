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


def cmd_scan(args):
    """Execute scan subcommand.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    
    # Load configuration
    config = Config(args.config if args.config else None)
    if args.timeout:
        config.timeout = args.timeout
    if args.workers:
        config.max_workers = args.workers
    
    # Initialize components
    plugin_manager = PluginManager(args.plugins_dir)
    logger.info(f"Loaded {plugin_manager.get_plugin_count()} plugins")
    
    result_manager = ResultManager(config.output_dir)
    scanner = EndpointScanner(config, plugin_manager)
    
    # Validate target URL
    if not scanner.validate_url(args.target):
        logger.error(f"Invalid target URL: {args.target}")
        sys.exit(1)
    
    # Load custom paths if provided
    paths = None
    if args.paths:
        try:
            with open(args.paths, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(paths)} custom paths from {args.paths}")
        except Exception as e:
            logger.error(f"Failed to load paths file: {e}")
            sys.exit(1)
    
    # Perform scan
    print(f"\n🔴 Starting RedCortex scan of {args.target}")
    print("="*60)
    
    try:
        results = scanner.scan_target(args.target, paths)
        
        # Save results
        scan_id = args.scan_id if args.scan_id else None
        output_file = result_manager.save_results(results, args.target, scan_id)
        
        # Generate and display report
        report = result_manager.generate_report(results, format='text')
        print("\n" + report)
        
        print(f"\n✓ Scan complete. Results saved to: {output_file}")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"✓ Report saved to: {args.output}")
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        print("\nScan interrupted.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        print(f"\n✗ Scan failed: {e}")
        sys.exit(1)


def cmd_resume(args):
    """Resume a previous scan.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Attempting to resume scan: {args.scan_id}")
    
    result_manager = ResultManager()
    scan_data = result_manager.load_results(args.scan_id)
    
    if not scan_data:
        logger.error(f"Scan {args.scan_id} not found")
        print(f"✗ Scan {args.scan_id} not found")
        sys.exit(1)
    
    print(f"\nResuming scan {args.scan_id}")
    print(f"Target: {scan_data['target']}")
    print(f"Original scan time: {scan_data['timestamp']}")
    print("\nNote: Full resume functionality requires state management.")
    print("This shows the previous results. Use 'report' command to regenerate report.")


def cmd_report(args):
    """Generate report from scan results.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    result_manager = ResultManager()
    
    scan_data = result_manager.load_results(args.scan_id)
    
    if not scan_data:
        logger.error(f"Scan {args.scan_id} not found")
        print(f"✗ Scan {args.scan_id} not found")
        sys.exit(1)
    
    # Generate report
    results = scan_data.get('results', [])
    report_format = args.format if args.format else 'text'
    report = result_manager.generate_report(results, format=report_format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"✓ Report saved to: {args.output}")
    else:
        print(report)


def cmd_dashboard(args):
    """Start web dashboard.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    config = Config()
    result_manager = ResultManager(config.output_dir)
    
    port = args.port if args.port else config.dashboard_port
    dashboard = Dashboard(result_manager, port=port)
    
    try:
        dashboard.start()
    except Exception as e:
        logger.error(f"Dashboard failed: {e}")
        print(f"✗ Dashboard failed: {e}")
        sys.exit(1)


def cmd_list(args):
    """List available scans.
    
    Args:
        args: Parsed command-line arguments
    """
    result_manager = ResultManager()
    scans = result_manager.list_scans()
    
    if not scans:
        print("No scans found.")
        return
    
    print("\nAvailable scans:")
    print("="*80)
    for scan in scans:
        findings_str = f"{scan['findings_count']} findings" if scan['findings_count'] > 0 else "No findings"
        print(f"{scan['scan_id']:<20} {scan['target']:<40} {findings_str}")
        print(f"  Timestamp: {scan['timestamp']}")
        print()


def create_parser():
    """Create and configure argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='RedCortex',
        description='Modular Red Team Web Penetration Testing Framework',
        epilog='For detailed help on subcommands, use: %(prog)s <subcommand> --help'
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose/debug logging')
    parser.add_argument('--log-file', metavar='FILE',
                       help='Write logs to FILE')
    parser.add_argument('--config', metavar='FILE',
                       help='Configuration file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan subcommand
    scan_parser = subparsers.add_parser('scan', help='Scan a target URL')
    scan_parser.add_argument('target', help='Target URL to scan')
    scan_parser.add_argument('-p', '--paths', metavar='FILE',
                           help='File containing paths to scan (one per line)')
    scan_parser.add_argument('-t', '--timeout', type=int, metavar='SECONDS',
                           help='Request timeout in seconds')
    scan_parser.add_argument('-w', '--workers', type=int, metavar='N',
                           help='Number of concurrent workers')
    scan_parser.add_argument('-o', '--output', metavar='FILE',
                           help='Save report to FILE')
    scan_parser.add_argument('--scan-id', metavar='ID',
                           help='Custom scan ID (auto-generated if not provided)')
    scan_parser.add_argument('--plugins-dir', default='plugins',
                           help='Directory containing plugins (default: plugins)')
    
    # Resume subcommand
    resume_parser = subparsers.add_parser('resume', help='Resume a previous scan')
    resume_parser.add_argument('scan_id', help='Scan ID to resume')
    
    # Report subcommand
    report_parser = subparsers.add_parser('report', help='Generate report from scan results')
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
