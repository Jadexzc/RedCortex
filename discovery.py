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
    
    def __init__(self, target_url: str, threads: int = 10, 
                 paths: Optional[List[str]] = None, timeout: int = 8):
        """
        Initialize the EndpointScanner.
        
        Args:
            target_url: Base URL to scan
            threads: Number of concurrent workers
            paths: List of paths to scan (defaults to ['/'])
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.paths = paths or ['/']
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "RedCortex/1.0",
            "Accept": "*/*"
        })
        
    def scan_endpoint(self, url: str, path: str) -> Dict:
        """
        Scan a single endpoint and return results.
        
        Args:
            url: Base URL
            path: Path to append to base URL
            
        Returns:
            Dictionary containing scan results
        """
        full_url = urljoin(url, path)
        result = {
            'url': full_url,
            'path': path,
            'accessible': False,
            'status': None,
            'headers': {},
            'content_type': None,
            'content_length': 0,
            'redirect_url': None
        }
        
        try:
            response = self.session.get(
                full_url, 
                timeout=self.timeout, 
                allow_redirects=True,
                verify=True
            )
            
            result['accessible'] = True
            result['status'] = response.status_code
            result['headers'] = dict(response.headers)
            result['content_type'] = response.headers.get('Content-Type', '')
            result['content_length'] = len(response.content)
            
            # Track redirects
            if response.history:
                result['redirect_url'] = response.url
                
            # Log successful access
            logger.info(f"Endpoint {full_url} - Status: {response.status_code}")
            
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout accessing {full_url}")
            result['error'] = 'timeout'
            
        except requests.exceptions.SSLError as e:
            logger.debug(f"SSL error accessing {full_url}: {str(e)}")
            result['error'] = 'ssl_error'
            
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Connection error accessing {full_url}: {str(e)}")
            result['error'] = 'connection_error'
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error accessing {full_url}: {str(e)}")
            result['error'] = str(e)
            
        return result
    
    def scan_multiple(self) -> List[Dict]:
        """
        Scan multiple endpoints concurrently.
        
        Returns:
            List of scan results for all paths
        """
        logger.info(
            f"Scanning {self.target_url} with {len(self.paths)} paths "
            f"using {self.threads} workers"
        )
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {
                executor.submit(self.scan_endpoint, self.target_url, path): path
                for path in self.paths
            }
            
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Failed to scan {path}: {str(e)}")
                    results.append({
                        'url': urljoin(self.target_url, path),
                        'path': path,
                        'accessible': False,
                        'status': None,
                        'error': f"scan_failed: {str(e)}"
                    })
        
        accessible_count = len([r for r in results if r['accessible']])
        logger.info(
            f"Scan complete. {accessible_count}/{len(results)} "
            f"accessible endpoints found."
        )
        
        return results
    
    def get_accessible_endpoints(self, results: List[Dict]) -> List[Dict]:
        """
        Filter results to only accessible endpoints.
        
        Args:
            results: List of scan results
            
        Returns:
            List of accessible endpoints
        """
        return [r for r in results if r.get('accessible', False)]
    
    def close(self):
        """Close the session and cleanup resources."""
        if self.session:
            self.session.close()
            logger.debug("Scanner session closed")
