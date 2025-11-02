"""Dynamic plugin management for RedCortex.
Loads and manages security scanning plugins from the plugins directory.
"""
import os
import sys
import importlib.util
import logging
import traceback
from typing import List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class PluginManager:
    """Manager for dynamically loading and executing security plugins.
    
    Plugins should be placed in the plugins/ directory and must implement
    a run() method that accepts response and url parameters.
    """

    def __init__(self, plugins_dir: str = 'plugins'):
        """Initialize the plugin manager.
        
        Args:
            plugins_dir: Directory containing plugin modules
        """
        self.plugins_dir = plugins_dir
        self.plugins = []
        self._load_plugins()
        if not self.plugins:
            logger.warning("No plugins loaded at startup. Ensure plugins/ has at least one plugin.")
    
    def _load_plugins(self):
        """Load all plugins from the plugins directory."""
        plugins_path = Path(self.plugins_dir)
        
        if not plugins_path.exists():
            logger.warning(f"Plugins directory '{self.plugins_dir}' does not exist")
            return
        
        # Find all Python files in plugins directory
        plugin_files = list(plugins_path.glob('*.py'))
        plugin_files = [f for f in plugin_files if not f.name.startswith('_')]
        
        logger.info(f"Loading plugins from {self.plugins_dir}")
        
        for plugin_file in plugin_files:
            try:
                # Load the plugin module
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                assert spec and spec.loader
                spec.loader.exec_module(module)
                
                # Check if module has a run function
                if hasattr(module, 'run'):
                    self.plugins.append({
                        'name': module_name,
                        'module': module,
                        'description': getattr(module, '__doc__', 'No description')
                    })
                    logger.info(f"Loaded plugin: {module_name}")
                else:
                    logger.warning(f"Plugin {module_name} does not have a run() method")
                    
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file.name}: {e}\n{traceback.format_exc()}")
    
    def run_plugins(self, response, url: str) -> List[Dict[str, Any]]:
        """Run all loaded plugins on a response.
        
        Args:
            response: HTTP response object
            url: URL that was scanned
            
        Returns:
            List of findings from all plugins
        """
        findings: List[Dict[str, Any]] = []
        
        if not self.plugins:
            logger.warning("No plugins loaded. Run results will be empty.")
            return findings
        
        for plugin in self.plugins:
            try:
                logger.debug(f"Running plugin: {plugin['name']} on {url}")
                result = plugin['module'].run(response, url)
                
                if result:
                    # Ensure result is a list
                    if isinstance(result, dict):
                        result = [result]
                    
                    # Add plugin name to each finding
                    for finding in result:
                        if isinstance(finding, dict):
                            finding['plugin'] = plugin['name']
                            # Normalize keys to documented model when possible
                            finding.setdefault('url', url)
                            finding.setdefault('type', finding.get('type', 'unknown'))
                            finding.setdefault('severity', finding.get('severity', 'info'))
                            findings.append(finding)
            except Exception as e:
                logger.error(
                    f"Error running plugin {plugin.get('name')} on {url}: {e}\n{traceback.format_exc()}"
                )
        
        return findings

    def run_all(self, endpoints: List) -> List[Dict[str, Any]]:
        """
        Run all plugins for each endpoint result in the endpoints list.
        Each entry: usually a dict with keys 'url' or simply a URL string.
        Returns: list of all findings across all endpoints/plugins.
        """
        all_findings: List[Dict[str, Any]] = []
        for ep in endpoints:
            url = ep['url'] if isinstance(ep, dict) and 'url' in ep else ep
            response = ep.get('response', None) if isinstance(ep, dict) else None
            findings = self.run_plugins(response, url)
            if findings:
                all_findings.extend(findings)
        return all_findings

    def list_plugins(self) -> List[Dict[str, str]]:
        """List all loaded plugins.
        
        Returns:
            List of plugin information dictionaries
        """
        return [
            {
                'name': p['name'],
                'description': p['description']
            }
            for p in self.plugins
        ]
    
    def get_plugin_count(self) -> int:
        """Get the number of loaded plugins.
        
        Returns:
            Number of plugins loaded
        """
        return len(self.plugins)
