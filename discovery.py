"""
Endpoint discovery and scanning module for RedCortex.
Performs concurrent and adaptive endpoint analysis with plugin hooks.
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
    Handles multi-path brute-forcing, session setup, and plugin checks.
    """

    def __init__(self, target_url: str, plugins, threads: int = 10, paths: Optional[List[str]] = None, timeout: int = 8):
        self.target_url = target_url
        self.paths = paths or ['/']
        self.plugin_manager = plugins  
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "RedCortex"})

    def scan_endpoint(self, url: str, path: str) -> Dict:
        full_url = urljoin(url, path)
        result = {
            'url': full_url,
            'path': path,
            'accessible': False,
            'status': None,
            'findings': []
        }
        try:
            response = self.session.get(full_url, timeout=self.timeout, allow_redirects=True)
            result['accessible'] = True
            result['status'] = response.status_code
            if self.plugin_manager:
                findings = self.plugin_manager.run_plugins(response, full_url)
                result['findings'] = findings
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout accessing {full_url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error accessing {full_url}: {str(e)}")
        return result

    def scan_multiple(self) -> List[Dict]:
        logger.info(f"Scanning {self.target_url} with {len(self.paths)} paths using {self.threads} workers")
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {
                executor.submit(self.scan_endpoint, self.target_url, path): path
                for path in self.paths
            }
            for future in as_completed(future_to_path):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Failed to scan {future_to_path[future]}: {str(e)}")
        logger.info(f"Scan complete. {len([r for r in results if r['accessible']])} accessible endpoints found.")
        return results
