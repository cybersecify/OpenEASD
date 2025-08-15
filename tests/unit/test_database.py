"""Unit tests for database operations."""

import pytest
from datetime import datetime
from core.database import DatabaseManager


class TestDatabaseManager:
    """Test cases for DatabaseManager."""
    
    def test_create_scan_session(self, temp_db):
        """Test creating a scan session."""
        session_id = temp_db.create_scan_session(
            domain='test.com',
            scan_type='full',
            config_hash='abc123'
        )
        
        assert isinstance(session_id, int)
        assert session_id > 0
        
        # Verify session was created
        session = temp_db.get_scan_session(session_id)
        assert session['domain'] == 'test.com'
        assert session['scan_type'] == 'full'
        assert session['config_hash'] == 'abc123'
        assert session['status'] == 'running'
    
    def test_update_scan_session(self, temp_db):
        """Test updating scan session status."""
        session_id = temp_db.create_scan_session('test.com', 'full')
        
        temp_db.update_scan_session(
            session_id,
            status='completed',
            total_findings=5
        )
        
        session = temp_db.get_scan_session(session_id)
        assert session['status'] == 'completed'
        assert session['total_findings'] == 5
    
    def test_insert_and_get_vulnerabilities(self, temp_db, sample_vulnerability):
        """Test inserting and retrieving vulnerabilities."""
        session_id = temp_db.create_scan_session('test.com', 'full')
        
        vulnerabilities = [sample_vulnerability]
        temp_db.insert_vulnerabilities(session_id, vulnerabilities)
        
        retrieved = temp_db.get_vulnerabilities(session_id)
        assert len(retrieved) == 1
        assert retrieved[0]['host'] == 'test.com'
        assert retrieved[0]['vulnerability_type'] == 'missing_security_headers'
    
    def test_insert_and_get_services(self, temp_db, sample_service):
        """Test inserting and retrieving services."""
        session_id = temp_db.create_scan_session('test.com', 'full')
        
        services = [sample_service]
        temp_db.insert_services(session_id, services)
        
        retrieved = temp_db.get_services(session_id)
        assert len(retrieved) == 1
        assert retrieved[0]['host'] == 'test.com'
        assert retrieved[0]['port'] == 80
    
    def test_insert_and_get_subdomains(self, temp_db, sample_subdomain):
        """Test inserting and retrieving subdomains."""
        session_id = temp_db.create_scan_session('test.com', 'full')
        
        subdomains = [sample_subdomain]
        temp_db.insert_subdomains(session_id, subdomains)
        
        retrieved = temp_db.get_subdomains(session_id)
        assert len(retrieved) == 1
        assert retrieved[0]['subdomain'] == 'www.test.com'
    
    def test_get_latest_session(self, temp_db):
        """Test getting latest scan session."""
        # Create multiple sessions
        session1 = temp_db.create_scan_session('test.com', 'full')
        session2 = temp_db.create_scan_session('test.com', 'incremental')
        session3 = temp_db.create_scan_session('other.com', 'full')
        
        # Get latest for test.com
        latest = temp_db.get_latest_session('test.com')
        assert latest['id'] == session2  # Most recent
        
        # Get latest full scan for test.com
        latest_full = temp_db.get_latest_session('test.com', 'full')
        assert latest_full['id'] == session1
    
    def test_vulnerability_filtering_by_severity(self, temp_db):
        """Test filtering vulnerabilities by severity."""
        session_id = temp_db.create_scan_session('test.com', 'full')
        
        vulnerabilities = [
            {**sample_vulnerability, 'severity': 'critical'},
            {**sample_vulnerability, 'severity': 'medium'},
            {**sample_vulnerability, 'severity': 'low'}
        ]
        
        # Fix the reference to sample_vulnerability
        for i, vuln in enumerate(vulnerabilities):
            vuln.update({
                'host': 'test.com',
                'vulnerability_type': f'test_vuln_{i}',
                'title': f'Test Vulnerability {i}',
                'description': f'Test description {i}'
            })
        
        temp_db.insert_vulnerabilities(session_id, vulnerabilities)
        
        # Test filtering
        critical_vulns = temp_db.get_vulnerabilities(session_id, 'critical')
        assert len(critical_vulns) == 1
        assert critical_vulns[0]['severity'] == 'critical'
        
        all_vulns = temp_db.get_vulnerabilities(session_id)
        assert len(all_vulns) == 3
    
    def test_scan_statistics(self, temp_db):
        """Test getting scan statistics."""
        # Create some test data
        session1 = temp_db.create_scan_session('test.com', 'full')
        session2 = temp_db.create_scan_session('test.com', 'incremental')
        
        temp_db.update_scan_session(session1, status='completed', total_findings=10)
        temp_db.update_scan_session(session2, status='completed', total_findings=5)
        
        # Add some vulnerabilities
        vulnerabilities = [
            {'host': 'test.com', 'vulnerability_type': 'test1', 'severity': 'high', 'title': 'Test 1', 'description': 'Test'},
            {'host': 'test.com', 'vulnerability_type': 'test2', 'severity': 'medium', 'title': 'Test 2', 'description': 'Test'}
        ]
        temp_db.insert_vulnerabilities(session1, vulnerabilities)
        
        stats = temp_db.get_scan_statistics('test.com', 30)
        
        assert stats['total_scans'] == 2
        assert stats['successful_scans'] == 2
        assert stats['failed_scans'] == 0
        assert stats['avg_findings'] == 7.5  # (10 + 5) / 2
        assert 'vulnerability_counts' in stats
    
    def test_cleanup_old_scans(self, temp_db):
        """Test cleaning up old scan data."""
        # Create a test session
        session_id = temp_db.create_scan_session('test.com', 'full')
        
        # This test would need to manipulate timestamps to test properly
        # For now, just verify the method exists and runs
        deleted_count = temp_db.cleanup_old_scans(90)
        assert isinstance(deleted_count, int)
        assert deleted_count >= 0


def sample_vulnerability():
    """Helper function to create sample vulnerability data."""
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