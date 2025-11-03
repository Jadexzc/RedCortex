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
