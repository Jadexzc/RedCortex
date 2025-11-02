"""Configuration management for RedCortex.

Handles configuration from files and environment variables with fallback support.
"""
import os
import json
from typing import Dict, List, Optional


class Config:
    """Configuration manager for RedCortex scanner.
    
    Supports loading configuration from config file and environment variables.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_file: Path to JSON configuration file (optional)
        """
        self.config_file = config_file
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file or environment variables."""
        # Default configuration
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        self.tokens = [
            'admin', 'token', 'api_key', 'secret', 'password',
            'access_token', 'auth', 'key', 'session'
        ]
        
        self.paths = [
            '/admin', '/api', '/config', '/backup', '/database',
            '/login', '/dashboard', '/users', '/upload', '/.git',
            '/.env', '/wp-admin', '/phpmyadmin', '/debug',
            '/test', '/dev', '/swagger', '/api/v1', '/graphql'
        ]
        
        self.timeout = 10
        self.max_workers = 10
        self.output_dir = 'results'
        self.log_file = 'redcortex.log'
        self.dashboard_port = 8080
        
        # Load from config file if provided
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    self._merge_config(file_config)
            except Exception as e:
                print(f"Warning: Failed to load config file: {e}")
        
        # Override with environment variables
        self._load_from_env()
    
    def _merge_config(self, file_config: Dict):
        """Merge file configuration with defaults.
        
        Args:
            file_config: Configuration dictionary from file
        """
        if 'user_agents' in file_config:
            self.user_agents = file_config['user_agents']
        if 'tokens' in file_config:
            self.tokens = file_config['tokens']
        if 'paths' in file_config:
            self.paths = file_config['paths']
        if 'timeout' in file_config:
            self.timeout = file_config['timeout']
        if 'max_workers' in file_config:
            self.max_workers = file_config['max_workers']
        if 'output_dir' in file_config:
            self.output_dir = file_config['output_dir']
        if 'log_file' in file_config:
            self.log_file = file_config['log_file']
        if 'dashboard_port' in file_config:
            self.dashboard_port = file_config['dashboard_port']
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        if os.getenv('REDCORTEX_TIMEOUT'):
            self.timeout = int(os.getenv('REDCORTEX_TIMEOUT'))
        if os.getenv('REDCORTEX_MAX_WORKERS'):
            self.max_workers = int(os.getenv('REDCORTEX_MAX_WORKERS'))
        if os.getenv('REDCORTEX_OUTPUT_DIR'):
            self.output_dir = os.getenv('REDCORTEX_OUTPUT_DIR')
        if os.getenv('REDCORTEX_LOG_FILE'):
            self.log_file = os.getenv('REDCORTEX_LOG_FILE')
        if os.getenv('REDCORTEX_DASHBOARD_PORT'):
            self.dashboard_port = int(os.getenv('REDCORTEX_DASHBOARD_PORT'))
    
    def get_user_agent(self) -> str:
        """Get a random user agent.
        
        Returns:
            Random user agent string
        """
        import random
        return random.choice(self.user_agents)
    
    def get_paths(self) -> List[str]:
        """Get list of paths to scan.
        
        Returns:
            List of paths
        """
        return self.paths
    
    def get_tokens(self) -> List[str]:
        """Get list of tokens to search for.
        
        Returns:
            List of token keywords
        """
        return self.tokens
