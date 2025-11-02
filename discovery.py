"""Endpoint discovery module for RedCortex.
Handles scanning endpoints for vulnerabilities and exposures.
"""
import requests
import logging
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class EndpointScanner:
    """Scanner for discovering and analyzing endpoints.
    
    Performs concurrent scanning of multiple endpoints for security issues.
    """
    
    def __init__(self, config, plugin_manager):
        """Initialize the endpoint scanner.
        
        Args:
            config: Configuration object
            plugin_manager: Plugin manager for running security checks
        """
        self.config = config
        self.plugin_manager = plugin_manager
        self.timeout = config.timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a configured requests session.
        
        Returns:
            Configured requests session
        """
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.config.get_user_agent()
        })
        return session
    
    def discover(self):
        '''
        Discover endpoints for scanning. Returns a list of endpoint URLs.
        '''
        if hasattr(self.config, 'target_url'):
            return [self.config.target_url]
        return []
    
    def scan_endpoint(self, url: str, path: str) -> Dict:
        """Scan a single endpoint.
        
        Args:
            url: Base URL to scan
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
            'findings': []
        }
        
        try:
            response = self.session.get(full_url, timeout=self.timeout, allow_redirects=True)
            result['accessible'] = True
            result['status'] = response.status_code
            
            # Run plugins on the response
            if self.plugin_manager:
                findings = self.plugin_manager.run_plugins(response, full_url)
                result['findings'] = findings
                
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout accessing {full_url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error accessing {full_url}: {str(e)}")
        
        return result
    
    def scan_multiple(self, target_url: str, paths: Optional[List[str]] = None) -> List[Dict]:
        """Scan multiple endpoints concurrently.
        
        Args:
            target_url: Base URL to scan
            paths: List of paths to scan (defaults to config paths if None)
            
        Returns:
            List of scan results
        """
        if paths is None:
            paths = self.config.get_paths()
        
        logger.info(f"Starting scan of {target_url} with {len(paths)} paths")
        logger.info(f"Using {self.config.max_workers} concurrent workers")
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all scan tasks
            future_to_path = {
                executor.submit(self.scan_endpoint, target_url, path): path
                for path in paths
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Log significant findings
                    if result['accessible']:
                        logger.info(f"✓ {result['url']} - Status: {result['status']}")
                        if result['findings']:
                            for finding in result['findings']:
                                logger.warning(f"  ⚠ {finding['severity']}: {finding['description']}")
                    
                except Exception as e:
                    logger.error(f"Failed to scan path {path}: {str(e)}")
        
        logger.info(f"Scan complete. Found {len([r for r in results if r['accessible']])} accessible endpoints")
        return results
    
    def validate_url(self, url: str) -> bool:
        """Validate if URL is properly formatted.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
