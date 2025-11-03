"""Endpoint discovery and scanning module for RedCortex.
Performs concurrent and adaptive endpoint analysis.
"""
import requests
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class EndpointScanner:
    """
    Discovers and scans endpoints for vulnerabilities.
    
    Handles multi-path brute-forcing, session setup, and response analysis.
    """
    
    def __init__(self, target_url, plugin_manager, threads=10, paths=None, timeout=8):
        """
        Initialize the EndpointScanner.
        
        Args:
            target_url: Base URL to scan
            plugin_manager: Plugin manager instance
            threads: Number of concurrent workers
            paths: List of paths to scan (defaults to ['/'])
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.plugin_manager = plugin_manager
        self.paths = paths or ['/']
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
    
    def scan_multiple(self) -> List[Dict]:
        """
        Scan multiple endpoints with all loaded plugins.
        
        Returns:
            List of scan results from all plugins
        """
        results = []
        logger.info(f"Starting scan on {self.target_url} with {len(self.paths)} path(s)")
        
        for path in self.paths:
            endpoint = urljoin(self.target_url, path)
            logger.info(f"Scanning endpoint: {endpoint}")
            
            # Run all plugins against this endpoint
            plugin_results = self.plugin_manager.run_plugins(endpoint, self.session)
            results.extend(plugin_results)
        
        logger.info(f"Scan completed. Found {len(results)} result(s)")
        return results
    
    def run(self) -> List[Dict]:
        """
        Run the scanner (alias for scan_multiple for backwards compatibility).
        
        Returns:
            List of scan results from all plugins
        """
        return self.scan_multiple()
