"""Pytest configuration and shared fixtures for OpenEASD tests."""

import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.database import DatabaseManager
from core.config_manager import ConfigManager


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    db = DatabaseManager(db_path)
    yield db
    
    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def test_config():
    """Create test configuration."""
    config_data = {
        'target': {
            'primary_domain': 'test.com',
            'excluded_subdomains': [],
            'scan_depth': 2
        },
        'tools': {
            'subfinder': {'enabled': True, 'timeout': 60},
            'naabu': {'enabled': True, 'timeout': 60},
            'nmap': {'enabled': True, 'timeout': 60},
            'nuclei': {'enabled': True, 'timeout': 60}
        },
        'alerts': {
            'slack': {'enabled': False},
            'email': {'enabled': False}
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
        import yaml
        yaml.dump(config_data, tmp)
        config_path = tmp.name
    
    config = ConfigManager(config_path)
    yield config
    
    # Cleanup
    if os.path.exists(config_path):
        os.unlink(config_path)


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability data for testing."""
    return {
        'host': 'test.com',
        'port': 80,
        'vulnerability_type': 'missing_security_headers',
        'severity': 'medium',
        'title': 'Missing Security Headers',
        'description': 'Security headers not properly configured',
        'remediation': 'Configure security headers',
        'discovered_at': '2024-01-01T00:00:00',
        'tool': 'nuclei'
    }


@pytest.fixture
def sample_service():
    """Sample service data for testing."""
    return {
        'host': 'test.com',
        'port': 80,
        'service_name': 'http',
        'version': 'nginx/1.18.0',
        'protocol': 'tcp',
        'state': 'open',
        'discovered_at': '2024-01-01T00:00:00',
        'tool': 'nmap'
    }


@pytest.fixture
def sample_subdomain():
    """Sample subdomain data for testing."""
    return {
        'subdomain': 'www.test.com',
        'ip_address': '192.168.1.1',
        'discovered_at': '2024-01-01T00:00:00',
        'tool': 'subfinder'
    }