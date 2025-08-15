"""Configuration management for OpenEASD."""

import yaml
import os
import hashlib
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages configuration settings for OpenEASD."""
    
    def __init__(self, config_path: str = "config/default_config.yaml"):
        self.config_path = config_path
        self.config_data = {}
        self._load_config()
        self._apply_environment_overrides()
    
    def _load_config(self):
        """Load configuration from YAML file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config_data = yaml.safe_load(f) or {}
                logger.info(f"Configuration loaded from {self.config_path}")
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
                self.config_data = self._get_default_config()
                
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self.config_data = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'target': {
                'primary_domain': 'example.com',
                'excluded_subdomains': [],
                'scan_depth': 3,
                'max_subdomains': 1000
            },
            'tools': {
                'subfinder': {
                    'sources': ['crtsh', 'virustotal', 'securitytrails'],
                    'timeout': 300,
                    'rate_limit': 100
                },
                'naabu': {
                    'top_ports': 1000,
                    'rate': 1000,
                    'timeout': 5000
                },
                'nmap': {
                    'timing': 3,
                    'scripts': ['default', 'safe'],
                    'timeout': 600
                },
                'nuclei': {
                    'templates': ['cves', 'misconfigurations', 'default-logins'],
                    'rate_limit': 150,
                    'timeout': 30
                }
            },
            'alerts': {
                'slack': {
                    'webhook_url': '',
                    'channel': '#security-alerts',
                    'severity_threshold': 'medium',
                    'enabled': False
                },
                'email': {
                    'smtp_server': '',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'to_addresses': [],
                    'severity_threshold': 'high',
                    'enabled': False
                }
            },
            'performance': {
                'max_concurrent_scans': 5,
                'scan_timeout': 3600,
                'retry_attempts': 3,
                'rate_limit_delay': 1
            },
            'database': {
                'path': 'data/openeasd.db',
                'retention_days': 90,
                'backup_enabled': True
            },
            'logging': {
                'level': 'INFO',
                'file_path': 'logs/openeasd.log',
                'max_file_size': '10MB',
                'backup_count': 5
            },
            'security': {
                'api_key_required': False,
                'allowed_domains': [],
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 60
                }
            }
        }
    
    def _apply_environment_overrides(self):
        """Apply environment variable overrides to configuration."""
        env_mappings = {
            'SLACK_WEBHOOK_URL': 'alerts.slack.webhook_url',
            'EMAIL_SMTP_SERVER': 'alerts.email.smtp_server',
            'EMAIL_USERNAME': 'alerts.email.username',
            'EMAIL_PASSWORD': 'alerts.email.password',
            'DATABASE_PATH': 'database.path',
            'LOG_LEVEL': 'logging.level',
            'MAX_CONCURRENT_SCANS': 'performance.max_concurrent_scans',
            'SCAN_TIMEOUT': 'performance.scan_timeout',
            'PRIMARY_DOMAIN': 'target.primary_domain'
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value:
                self._set_nested_value(config_path, env_value)
                logger.debug(f"Applied environment override: {env_var} -> {config_path}")
    
    def _set_nested_value(self, key_path: str, value: Any):
        """Set nested configuration value using dot notation."""
        keys = key_path.split('.')
        current = self.config_data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Convert string values to appropriate types
        if isinstance(value, str):
            if value.lower() in ('true', 'false'):
                value = value.lower() == 'true'
            elif value.isdigit():
                value = int(value)
            elif value.replace('.', '', 1).isdigit():
                value = float(value)
        
        current[keys[-1]] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        keys = key_path.split('.')
        current = self.config_data
        
        try:
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """Set configuration value using dot notation."""
        self._set_nested_value(key_path, value)
    
    def get_dict(self) -> Dict[str, Any]:
        """Get entire configuration as dictionary."""
        return self.config_data.copy()
    
    def get_config_hash(self) -> str:
        """Generate hash of current configuration for change detection."""
        config_str = json.dumps(self.config_data, sort_keys=True)
        return hashlib.md5(config_str.encode()).hexdigest()
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Validate required fields
        required_fields = [
            'target.primary_domain',
            'database.path'
        ]
        
        for field in required_fields:
            if not self.get(field):
                issues.append(f"Required field missing or empty: {field}")
        
        # Validate tool configurations
        tools = self.get('tools', {})
        for tool_name, tool_config in tools.items():
            if not isinstance(tool_config, dict):
                issues.append(f"Tool configuration must be a dictionary: {tool_name}")
                continue
            
            # Validate timeout values
            timeout = tool_config.get('timeout')
            if timeout and (not isinstance(timeout, int) or timeout <= 0):
                issues.append(f"Invalid timeout for {tool_name}: must be positive integer")
        
        # Validate alert configurations
        alerts = self.get('alerts', {})
        for alert_type, alert_config in alerts.items():
            if alert_config.get('enabled', False):
                if alert_type == 'slack':
                    if not alert_config.get('webhook_url'):
                        issues.append("Slack webhook URL required when Slack alerts enabled")
                elif alert_type == 'email':
                    required_email_fields = ['smtp_server', 'username', 'password', 'to_addresses']
                    for field in required_email_fields:
                        if not alert_config.get(field):
                            issues.append(f"Email alert field required: {field}")
        
        # Validate performance settings
        performance = self.get('performance', {})
        max_concurrent = performance.get('max_concurrent_scans', 5)
        if not isinstance(max_concurrent, int) or max_concurrent <= 0:
            issues.append("max_concurrent_scans must be positive integer")
        
        scan_timeout = performance.get('scan_timeout', 3600)
        if not isinstance(scan_timeout, int) or scan_timeout <= 0:
            issues.append("scan_timeout must be positive integer")
        
        # Validate database path
        db_path = self.get('database.path')
        if db_path:
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                try:
                    os.makedirs(db_dir, exist_ok=True)
                except Exception as e:
                    issues.append(f"Cannot create database directory {db_dir}: {e}")
        
        return issues
    
    def save_config(self, output_path: str = None):
        """Save current configuration to file."""
        if not output_path:
            output_path = self.config_path
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            raise
    
    def reload_config(self):
        """Reload configuration from file."""
        self._load_config()
        self._apply_environment_overrides()
        logger.info("Configuration reloaded")
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for specific tool."""
        return self.get(f'tools.{tool_name}', {})
    
    def get_alert_config(self, alert_type: str) -> Dict[str, Any]:
        """Get configuration for specific alert type."""
        return self.get(f'alerts.{alert_type}', {})
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if tool is enabled."""
        tool_config = self.get_tool_config(tool_name)
        return tool_config.get('enabled', True)  # Default to enabled
    
    def is_alert_enabled(self, alert_type: str) -> bool:
        """Check if alert type is enabled."""
        alert_config = self.get_alert_config(alert_type)
        return alert_config.get('enabled', False)  # Default to disabled
    
    def get_severity_threshold(self, alert_type: str) -> str:
        """Get severity threshold for alert type."""
        alert_config = self.get_alert_config(alert_type)
        return alert_config.get('severity_threshold', 'medium')
    
    def get_excluded_subdomains(self) -> List[str]:
        """Get list of excluded subdomains."""
        return self.get('target.excluded_subdomains', [])
    
    def add_excluded_subdomain(self, subdomain: str):
        """Add subdomain to exclusion list."""
        excluded = self.get_excluded_subdomains()
        if subdomain not in excluded:
            excluded.append(subdomain)
            self.set('target.excluded_subdomains', excluded)
    
    def remove_excluded_subdomain(self, subdomain: str):
        """Remove subdomain from exclusion list."""
        excluded = self.get_excluded_subdomains()
        if subdomain in excluded:
            excluded.remove(subdomain)
            self.set('target.excluded_subdomains', excluded)
    
    def get_nuclei_templates(self) -> List[str]:
        """Get list of Nuclei templates to use."""
        return self.get('tools.nuclei.templates', ['cves', 'misconfigurations'])
    
    def set_nuclei_templates(self, templates: List[str]):
        """Set Nuclei templates to use."""
        self.set('tools.nuclei.templates', templates)
    
    def get_performance_settings(self) -> Dict[str, Any]:
        """Get performance-related settings."""
        return self.get('performance', {})
    
    def optimize_for_environment(self, environment: str):
        """Optimize configuration for specific environment."""
        if environment == 'development':
            self.set('performance.max_concurrent_scans', 2)
            self.set('performance.scan_timeout', 1800)  # 30 minutes
            self.set('tools.nmap.timing', 2)
            self.set('logging.level', 'DEBUG')
            
        elif environment == 'production':
            self.set('performance.max_concurrent_scans', 10)
            self.set('performance.scan_timeout', 7200)  # 2 hours
            self.set('tools.nmap.timing', 4)
            self.set('logging.level', 'INFO')
            
        elif environment == 'testing':
            self.set('performance.max_concurrent_scans', 1)
            self.set('performance.scan_timeout', 600)  # 10 minutes
            self.set('tools.nmap.timing', 5)  # Aggressive for testing
            self.set('logging.level', 'DEBUG')
        
        logger.info(f"Configuration optimized for {environment} environment")
    
    def export_config(self, format_type: str = 'yaml') -> str:
        """Export configuration in specified format."""
        if format_type.lower() == 'json':
            return json.dumps(self.config_data, indent=2, sort_keys=True)
        elif format_type.lower() == 'yaml':
            return yaml.dump(self.config_data, default_flow_style=False, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def import_config(self, config_string: str, format_type: str = 'yaml'):
        """Import configuration from string."""
        try:
            if format_type.lower() == 'json':
                imported_config = json.loads(config_string)
            elif format_type.lower() == 'yaml':
                imported_config = yaml.safe_load(config_string)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
            
            # Merge with existing configuration
            self._deep_merge(self.config_data, imported_config)
            logger.info(f"Configuration imported from {format_type}")
            
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            raise
    
    def _deep_merge(self, base_dict: Dict, update_dict: Dict) -> Dict:
        """Deep merge two dictionaries."""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
        return base_dict