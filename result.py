"""Result management for RedCortex.

Handles scan results including saving, loading, and reporting.
"""
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class ResultManager:
    """Manager for handling scan results.

    Provides functionality for saving, loading, and generating reports from scan results.
    """

    def __init__(self, output_dir: str = 'results'):
        """Initialize the result manager.

        Args:
            output_dir: Directory to store results
        """
        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        """Create output directory if it doesn't exist."""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def save_results(self, scan_data: Dict, scan_id: Optional[str] = None) -> str:
        """Save scan data dictionary to a JSON file.

        Args:
            scan_data: Dictionary containing scan results and metadata
            scan_id: Optional scan ID (generated if not provided)

        Returns:
            Path to saved results file
        """
        if scan_id is None:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')

        scan_data['scan_id'] = scan_id
        scan_data['timestamp'] = scan_data.get('timestamp', datetime.now().isoformat())
        scan_data['results'] = scan_data.get('results', scan_data.get('endpoints', []))
        scan_data['accessible_count'] = len([r for r in scan_data['results'] if r.get('accessible')])
        scan_data['findings_count'] = sum(len(r.get('findings', [])) for r in scan_data['results'])

        filename = f"scan_{scan_id}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, 'w') as f:
                json.dump(scan_data, f, indent=2)
            logger.info(f"Results saved to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")
            raise

    def load_results(self, scan_id: str) -> Optional[Dict]:
        """Load scan results from a file.

        Args:
            scan_id: Scan ID or filename to load

        Returns:
            Scan data dictionary or None if not found
        """
        # Handle both scan_id and full filename
        if not scan_id.endswith('.json'):
            filename = f"scan_{scan_id}.json"
        else:
            filename = scan_id

        filepath = os.path.join(self.output_dir, filename)

        try:
            if not os.path.exists(filepath):
                logger.error(f"Scan results not found: {filepath}")
                return None

            with open(filepath, 'r') as f:
                data = json.load(f)
            logger.info(f"Loaded results from {filepath}")
            return data
        except Exception as e:
            logger.error(f"Failed to load results: {str(e)}")
            return None

    def list_scans(self) -> List[Dict]:
        """List all saved scans.

        Returns:
            List of scan metadata dictionaries
        """
        scans = []

        try:
            for filename in os.listdir(self.output_dir):
                if filename.startswith('scan_') and filename.endswith('.json'):
                    filepath = os.path.join(self.output_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                            scans.append({
                                'scan_id': data.get('scan_id'),
                                'target': data.get('target'),
                                'timestamp': data.get('timestamp'),
                                'findings_count': data.get('findings_count', 0)
                            })
                    except Exception as e:
                        logger.warning(f"Failed to read {filename}: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to list scans: {str(e)}")

        return sorted(scans, key=lambda x: x.get('timestamp', ''), reverse=True)

    def generate_report(self, scan_data: Dict, format: str = 'text') -> str:
        """Generate a human-readable report from results.

        Args:
            scan_data: Dict containing all scan results and metadata
            format: Report format ('text' or 'markdown')

        Returns:
            Formatted report string
        """
        results = scan_data['results'] if 'results' in scan_data else []
        accessible = [r for r in results if r.get('accessible')]
        with_findings = [r for r in accessible if r.get('findings')]

        if format == 'markdown':
            return self._generate_markdown_report(scan_data, results, accessible, with_findings)
        else:
            return self._generate_text_report(scan_data, results, accessible, with_findings)

    def _generate_text_report(self, scan_data, results, accessible, with_findings) -> str:
        lines = []
        lines.append("="*60)
        lines.append("RedCortex Scan Report")
        lines.append("="*60)
        lines.append(f"Target: {scan_data.get('target', '')}")
        lines.append(f"Scan ID: {scan_data.get('scan_id', '')}")
        lines.append(f"Timestamp: {scan_data.get('timestamp', '')}")
        lines.append(f"Total endpoints scanned: {len(results)}")
        lines.append(f"Accessible endpoints: {len(accessible)}")
        lines.append(f"Endpoints with findings: {len(with_findings)}")
        lines.append("="*60)
        lines.append("")

        if with_findings:
            lines.append("FINDINGS:")
            lines.append("-"*60)
            for result in with_findings:
                lines.append(f"\n[{result['url']}]")
                lines.append(f"Status: {result['status']}")
                for finding in result['findings']:
                    lines.append(f"  - {finding['severity']}: {finding['description']}")
                    lines.append(f"    Plugin: {finding['plugin']}")
        else:
            lines.append("No security findings detected.")

        return "\n".join(lines)

    def _generate_markdown_report(self, scan_data, results, accessible, with_findings) -> str:
        lines = []
        lines.append("# RedCortex Scan Report")
        lines.append("")
        lines.append("## Summary")
        lines.append(f"- **Target:** {scan_data.get('target', '')}")
        lines.append(f"- **Scan ID:** {scan_data.get('scan_id', '')}")
        lines.append(f"- **Timestamp:** {scan_data.get('timestamp', '')}")
        lines.append(f"- **Total endpoints scanned:** {len(results)}")
        lines.append(f"- **Accessible endpoints:** {len(accessible)}")
        lines.append(f"- **Endpoints with findings:** {len(with_findings)}")
        lines.append("")

        if with_findings:
            lines.append("## Findings")
            lines.append("")
            for result in with_findings:
                lines.append(f"### {result['url']}")
                lines.append(f"**Status:** {result['status']}\n")
                for finding in result['findings']:
                    lines.append(f"- **{finding['severity']}**: {finding['description']}")
                    lines.append(f"  - *Plugin:* {finding['plugin']}")
                lines.append("")
        else:
            lines.append("## No Findings")
            lines.append("No security findings detected.")

        return "\n".join(lines)
