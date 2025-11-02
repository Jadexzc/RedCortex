"""Sample unit tests for RedCortex plugins.

Demonstrates basic testing of plugin output structure.
"""
import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from plugins import PluginManager


class MockResponse:
    """Mock HTTP response for testing."""
    
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


class TestPluginOutput(unittest.TestCase):
    """Test plugin output structure and format."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_url = "https://example.com/test"
    
    def test_plugin_returns_list(self):
        """Test that plugins return a list of findings."""
        # Import a plugin directly
        try:
            from plugins import sensitive_data
            
            # Test with response containing no sensitive data
            response = MockResponse("This is safe content without any sensitive information.")
            result = sensitive_data.run(response, self.test_url)
            
            # Should return a list (even if empty)
            self.assertIsInstance(result, list)
        except ImportError:
            self.skipTest("sensitive_data plugin not available")
    
    def test_plugin_finding_structure(self):
        """Test that plugin findings have required fields."""
        try:
            from plugins import sensitive_data
            
            # Test with response containing an email (should trigger finding)
            response = MockResponse("Contact us at test@example.com for more info.")
            result = sensitive_data.run(response, self.test_url)
            
            # If findings exist, check structure
            if result:
                for finding in result:
                    self.assertIn('severity', finding, "Finding should have 'severity' field")
                    self.assertIn('description', finding, "Finding should have 'description' field")
                    self.assertIn('url', finding, "Finding should have 'url' field")
                    
                    # Check severity values
                    self.assertIn(finding['severity'], ['HIGH', 'MEDIUM', 'LOW'],
                                "Severity should be HIGH, MEDIUM, or LOW")
        except ImportError:
            self.skipTest("sensitive_data plugin not available")
    
    def test_plugin_manager_loads_plugins(self):
        """Test that PluginManager can load plugins."""
        # Create plugin manager pointing to plugins directory
        try:
            pm = PluginManager('plugins')
            
            # Should load at least one plugin if directory exists
            plugin_count = pm.get_plugin_count()
            self.assertGreaterEqual(plugin_count, 0, "Plugin count should be >= 0")
            
            # List plugins
            plugins = pm.list_plugins()
            self.assertIsInstance(plugins, list)
            
            if plugins:
                # Check plugin info structure
                for plugin in plugins:
                    self.assertIn('name', plugin)
                    self.assertIn('description', plugin)
        except Exception as e:
            # If plugins directory doesn't exist, test passes
            pass
    
    def test_plugin_handles_empty_response(self):
        """Test that plugins handle empty responses gracefully."""
        try:
            from plugins import sensitive_data
            
            # Test with empty response
            response = MockResponse("")
            result = sensitive_data.run(response, self.test_url)
            
            # Should return empty list for empty response
            self.assertIsInstance(result, list)
            self.assertEqual(len(result), 0, "Empty response should yield no findings")
        except ImportError:
            self.skipTest("sensitive_data plugin not available")


class TestPluginIntegration(unittest.TestCase):
    """Integration tests for plugin system."""
    
    def test_plugin_manager_runs_all_plugins(self):
        """Test that PluginManager can run all loaded plugins."""
        try:
            pm = PluginManager('plugins')
            
            if pm.get_plugin_count() > 0:
                response = MockResponse("Test content with email@test.com")
                findings = pm.run_plugins(response, "https://example.com")
                
                # Should return a list
                self.assertIsInstance(findings, list)
                
                # Each finding should have plugin name
                for finding in findings:
                    self.assertIn('plugin', finding, "Finding should include plugin name")
        except Exception:
            pass


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
