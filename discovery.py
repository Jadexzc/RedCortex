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
    
    def scan_endpoint(self, url: str, path: str) -> Dict:
        """Scan a single endpoint.
        
        Args:
            url: Base URL to scan
            path: Path to append to base URL
            
        Returns:
            Dictionary with scan results
        """
        full_url = urljoin(url, path)
        result = {
            'url': full_url,
            'path': path,
            'status': None,
            'accessible': False,
            'findings': [],
            'error': None
        }
        
        try:
            logger.debug(f"Scanning endpoint: {full_url}")
            response = self.session.get(
                full_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            
            result['status'] = response.status_code
            result['accessible'] = response.status_code < 400
            
            if result['accessible']:
                logger.info(f"Found accessible endpoint: {full_url} (Status: {response.status_code})")
                
                # Run plugins on accessible endpoints
                plugin_results = self.plugin_manager.run_plugins(response, full_url)
                result['findings'].extend(plugin_results)
            
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout scanning {full_url}")
            result['error'] = 'timeout'
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error for {full_url}")
            result['error'] = 'connection_error'
        except Exception as e:
            logger.error(f"Error scanning {full_url}: {str(e)}")
            result['error'] = str(e)
        
        return result
    
    def scan_target(self, target_url: str, paths: Optional[List[str]] = None) -> List[Dict]:
        """Scan a target URL with multiple paths concurrently.
        
        Args:
            target_url: Base target URL
            paths: List of paths to scan (uses config default if None)
            
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
