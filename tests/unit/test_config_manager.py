"""Unit tests for configuration management."""

import pytest
import tempfile
import os
import yaml
from core.config_manager import ConfigManager


class TestConfigManager:
    """Test cases for ConfigManager."""
    
    def test_load_config_from_file(self, test_config):
        """Test loading configuration from YAML file."""
        assert test_config.get('target.primary_domain') == 'test.com'
        assert test_config.get('target.scan_depth') == 2
        assert test_config.get('tools.subfinder.enabled') is True
    
    def test_get_nested_values(self, test_config):
        """Test getting nested configuration values."""
        assert test_config.get('target.primary_domain') == 'test.com'
        assert test_config.get('tools.subfinder.timeout') == 60
        assert test_config.get('nonexistent.key', 'default') == 'default'
    
    def test_set_nested_values(self, test_config):
        """Test setting nested configuration values."""
        test_config.set('new.nested.key', 'test_value')
        assert test_config.get('new.nested.key') == 'test_value'
        
        test_config.set('target.primary_domain', 'updated.com')
        assert test_config.get('target.primary_domain') == 'updated.com'
    
    def test_config_validation(self, test_config):
        """Test configuration validation."""
        issues = test_config.validate_config()
        # Should have no issues with valid test config
        assert isinstance(issues, list)
    
    def test_invalid_config_validation(self):
        """Test validation with invalid configuration."""
        invalid_config = {
            'target': {'primary_domain': ''},  # Empty domain
            'tools': {
                'subfinder': {'timeout': -1}  # Invalid timeout
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            yaml.dump(invalid_config, tmp)
            config_path = tmp.name
        
        try:
            config = ConfigManager(config_path)
            issues = config.validate_config()
            
            assert len(issues) > 0
            assert any('primary_domain' in issue for issue in issues)
            
        finally:
            os.unlink(config_path)
    
    def test_environment_variable_overrides(self):
        """Test environment variable overrides."""
        # Set environment variable
        os.environ['SLACK_WEBHOOK_URL'] = 'https://test.webhook.url'
        
        config_data = {
            'alerts': {
                'slack': {'webhook_url': ''}
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            yaml.dump(config_data, tmp)
            config_path = tmp.name
        
        try:
            config = ConfigManager(config_path)
            # Should be overridden by environment variable
            assert config.get('alerts.slack.webhook_url') == 'https://test.webhook.url'
            
        finally:
            os.unlink(config_path)
            del os.environ['SLACK_WEBHOOK_URL']
    
    def test_tool_configuration(self, test_config):
        """Test tool-specific configuration methods."""
        subfinder_config = test_config.get_tool_config('subfinder')
        assert subfinder_config['enabled'] is True
        assert subfinder_config['timeout'] == 60
        
        assert test_config.is_tool_enabled('subfinder') is True
        assert test_config.is_tool_enabled('nonexistent_tool') is True  # Default
    
    def test_alert_configuration(self, test_config):
        """Test alert-specific configuration methods."""
        slack_config = test_config.get_alert_config('slack')
        assert slack_config['enabled'] is False
        
        assert test_config.is_alert_enabled('slack') is False
        assert test_config.is_alert_enabled('email') is False
        
        threshold = test_config.get_severity_threshold('slack')
        assert threshold == 'medium'  # Default
    
    def test_excluded_subdomains(self, test_config):
        """Test subdomain exclusion management."""
        excluded = test_config.get_excluded_subdomains()
        assert excluded == []
        
        test_config.add_excluded_subdomain('admin.test.com')
        excluded = test_config.get_excluded_subdomains()
        assert 'admin.test.com' in excluded
        
        test_config.remove_excluded_subdomain('admin.test.com')
        excluded = test_config.get_excluded_subdomains()
        assert 'admin.test.com' not in excluded
    
    def test_config_hash(self, test_config):
        """Test configuration hash generation."""
        hash1 = test_config.get_config_hash()
        assert isinstance(hash1, str)
        assert len(hash1) == 32  # MD5 hash length
        
        # Hash should be consistent
        hash2 = test_config.get_config_hash()
        assert hash1 == hash2
        
        # Hash should change when config changes
        test_config.set('new.key', 'value')
        hash3 = test_config.get_config_hash()
        assert hash1 != hash3
    
    def test_environment_optimization(self, test_config):
        """Test environment-specific optimizations."""
        # Test development optimization
        test_config.optimize_for_environment('development')
        assert test_config.get('performance.max_concurrent_scans') == 2
        assert test_config.get('logging.level') == 'DEBUG'
        
        # Test production optimization
        test_config.optimize_for_environment('production')
        assert test_config.get('performance.max_concurrent_scans') == 10
        assert test_config.get('logging.level') == 'INFO'
    
    def test_config_export_import(self, test_config):
        """Test configuration export and import."""
        # Export as JSON
        json_export = test_config.export_config('json')
        assert isinstance(json_export, str)
        assert 'test.com' in json_export
        
        # Export as YAML
        yaml_export = test_config.export_config('yaml')
        assert isinstance(yaml_export, str)
        assert 'test.com' in yaml_export
        
        # Test import
        new_config = {'new': {'imported': {'key': 'value'}}}
        import json
        test_config.import_config(json.dumps(new_config), 'json')
        assert test_config.get('new.imported.key') == 'value'
    
    def test_performance_settings(self, test_config):
        """Test performance-related settings."""
        perf_settings = test_config.get_performance_settings()
        assert isinstance(perf_settings, dict)
        
        # Should have default values since not set in test config
        max_scans = test_config.get('performance.max_concurrent_scans', 5)
        assert isinstance(max_scans, int)
    
    def test_nuclei_templates(self, test_config):
        """Test Nuclei template management."""
        # Set some templates
        templates = ['cves', 'misconfigurations']
        test_config.set_nuclei_templates(templates)
        
        retrieved = test_config.get_nuclei_templates()
        assert retrieved == templates
    
    def test_default_config_creation(self):
        """Test creation with non-existent config file."""
        # Try to load non-existent file
        config = ConfigManager('/path/that/does/not/exist.yaml')
        
        # Should use default config
        assert config.get('target.primary_domain') == 'example.com'
        assert isinstance(config.get_dict(), dict)
    
    def test_type_conversion_in_set(self, test_config):
        """Test automatic type conversion when setting values."""
        # Test with string that should become boolean
        test_config._set_nested_value('test.bool', 'true')
        assert test_config.get('test.bool') is True
        
        test_config._set_nested_value('test.bool', 'false')  
        assert test_config.get('test.bool') is False
        
        # Test with string that should become integer
        test_config._set_nested_value('test.int', '123')
        assert test_config.get('test.int') == 123
        
        # Test with string that should become float
        test_config._set_nested_value('test.float', '12.5')
        assert test_config.get('test.float') == 12.5