"""Delta detection for tracking changes between scans."""

import json
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class DeltaDetector:
    """Detects and analyzes changes between scan sessions."""
    
    def __init__(self, database_manager):
        self.db = database_manager
    
    def detect_changes(self, current_session_id: int, 
                      previous_session_id: int) -> List[Dict[str, Any]]:
        """
        Detect changes between two scan sessions.
        
        Args:
            current_session_id: ID of current scan session
            previous_session_id: ID of previous scan session
            
        Returns:
            List of detected changes
        """
        changes = []
        
        # Detect subdomain changes
        subdomain_changes = self._detect_subdomain_changes(
            current_session_id, previous_session_id
        )
        changes.extend(subdomain_changes)
        
        # Detect service changes
        service_changes = self._detect_service_changes(
            current_session_id, previous_session_id
        )
        changes.extend(service_changes)
        
        # Detect vulnerability changes
        vulnerability_changes = self._detect_vulnerability_changes(
            current_session_id, previous_session_id
        )
        changes.extend(vulnerability_changes)
        
        # Store changes in database
        for change in changes:
            self.db.insert_scan_delta(
                current_session_id,
                previous_session_id,
                change['change_type'],
                change['category'],
                change['identifier'],
                json.dumps(change.get('details', {}))
            )
        
        logger.info(f"Detected {len(changes)} changes between sessions "
                   f"{previous_session_id} and {current_session_id}")
        
        return changes
    
    def _detect_subdomain_changes(self, current_session_id: int, 
                                previous_session_id: int) -> List[Dict[str, Any]]:
        """Detect changes in subdomains."""
        changes = []
        
        # Get subdomains from both sessions
        current_subdomains = {
            sub['subdomain']: sub 
            for sub in self.db.get_subdomains(current_session_id)
        }
        
        previous_subdomains = {
            sub['subdomain']: sub 
            for sub in self.db.get_subdomains(previous_session_id)
        }
        
        # Detect new subdomains
        new_subdomains = set(current_subdomains.keys()) - set(previous_subdomains.keys())
        for subdomain in new_subdomains:
            changes.append({
                'change_type': 'new',
                'category': 'subdomain',
                'identifier': subdomain,
                'details': {
                    'subdomain': subdomain,
                    'ip_address': current_subdomains[subdomain].get('ip_address'),
                    'discovered_at': current_subdomains[subdomain].get('discovered_at')
                },
                'severity': 'medium',
                'description': f"New subdomain discovered: {subdomain}"
            })
        
        # Detect removed subdomains
        removed_subdomains = set(previous_subdomains.keys()) - set(current_subdomains.keys())
        for subdomain in removed_subdomains:
            changes.append({
                'change_type': 'removed',
                'category': 'subdomain',
                'identifier': subdomain,
                'details': {
                    'subdomain': subdomain,
                    'previous_ip_address': previous_subdomains[subdomain].get('ip_address')
                },
                'severity': 'low',
                'description': f"Subdomain no longer accessible: {subdomain}"
            })
        
        # Detect IP address changes
        common_subdomains = set(current_subdomains.keys()) & set(previous_subdomains.keys())
        for subdomain in common_subdomains:
            current_ip = current_subdomains[subdomain].get('ip_address')
            previous_ip = previous_subdomains[subdomain].get('ip_address')
            
            if current_ip != previous_ip and current_ip and previous_ip:
                changes.append({
                    'change_type': 'modified',
                    'category': 'subdomain',
                    'identifier': subdomain,
                    'details': {
                        'subdomain': subdomain,
                        'previous_ip': previous_ip,
                        'current_ip': current_ip
                    },
                    'severity': 'medium',
                    'description': f"IP address changed for {subdomain}: {previous_ip} -> {current_ip}"
                })
        
        return changes
    
    def _detect_service_changes(self, current_session_id: int, 
                              previous_session_id: int) -> List[Dict[str, Any]]:
        """Detect changes in services."""
        changes = []
        
        # Get services from both sessions
        current_services = self._index_services(self.db.get_services(current_session_id))
        previous_services = self._index_services(self.db.get_services(previous_session_id))
        
        # Detect new services
        new_service_keys = set(current_services.keys()) - set(previous_services.keys())
        for service_key in new_service_keys:
            service = current_services[service_key]
            severity = self._calculate_service_severity(service)
            
            changes.append({
                'change_type': 'new',
                'category': 'service',
                'identifier': service_key,
                'details': {
                    'host': service.get('host'),
                    'port': service.get('port'),
                    'service_name': service.get('service_name'),
                    'version': service.get('version'),
                    'protocol': service.get('protocol')
                },
                'severity': severity,
                'description': f"New service discovered: {service.get('service_name', 'Unknown')} "
                              f"on {service.get('host')}:{service.get('port')}"
            })
        
        # Detect removed services
        removed_service_keys = set(previous_services.keys()) - set(current_services.keys())
        for service_key in removed_service_keys:
            service = previous_services[service_key]
            
            changes.append({
                'change_type': 'removed',
                'category': 'service',
                'identifier': service_key,
                'details': {
                    'host': service.get('host'),
                    'port': service.get('port'),
                    'service_name': service.get('service_name'),
                    'protocol': service.get('protocol')
                },
                'severity': 'low',
                'description': f"Service no longer accessible: {service.get('service_name', 'Unknown')} "
                              f"on {service.get('host')}:{service.get('port')}"
            })
        
        # Detect service changes (version updates, etc.)
        common_service_keys = set(current_services.keys()) & set(previous_services.keys())
        for service_key in common_service_keys:
            current_service = current_services[service_key]
            previous_service = previous_services[service_key]
            
            # Check for version changes
            current_version = current_service.get('version', '')
            previous_version = previous_service.get('version', '')
            
            if current_version != previous_version and current_version and previous_version:
                changes.append({
                    'change_type': 'modified',
                    'category': 'service',
                    'identifier': service_key,
                    'details': {
                        'host': current_service.get('host'),
                        'port': current_service.get('port'),
                        'service_name': current_service.get('service_name'),
                        'previous_version': previous_version,
                        'current_version': current_version
                    },
                    'severity': 'medium',
                    'description': f"Service version changed: {current_service.get('service_name')} "
                                  f"on {current_service.get('host')}:{current_service.get('port')} "
                                  f"({previous_version} -> {current_version})"
                })
        
        return changes
    
    def _detect_vulnerability_changes(self, current_session_id: int, 
                                    previous_session_id: int) -> List[Dict[str, Any]]:
        """Detect changes in vulnerabilities."""
        changes = []
        
        # Get vulnerabilities from both sessions
        current_vulns = self._index_vulnerabilities(
            self.db.get_vulnerabilities(current_session_id)
        )
        previous_vulns = self._index_vulnerabilities(
            self.db.get_vulnerabilities(previous_session_id)
        )
        
        # Detect new vulnerabilities
        new_vuln_keys = set(current_vulns.keys()) - set(previous_vulns.keys())
        for vuln_key in new_vuln_keys:
            vuln = current_vulns[vuln_key]
            
            changes.append({
                'change_type': 'new',
                'category': 'vulnerability',
                'identifier': vuln_key,
                'details': {
                    'host': vuln.get('host'),
                    'port': vuln.get('port'),
                    'vulnerability_type': vuln.get('vulnerability_type'),
                    'severity': vuln.get('severity'),
                    'title': vuln.get('title'),
                    'description': vuln.get('description'),
                    'cvss_score': vuln.get('cvss_score'),
                    'cve_id': vuln.get('cve_id')
                },
                'severity': vuln.get('severity', 'medium'),
                'description': f"New vulnerability: {vuln.get('title', vuln.get('vulnerability_type'))} "
                              f"on {vuln.get('host')}" + 
                              (f":{vuln.get('port')}" if vuln.get('port') else "")
            })
        
        # Detect resolved vulnerabilities
        resolved_vuln_keys = set(previous_vulns.keys()) - set(current_vulns.keys())
        for vuln_key in resolved_vuln_keys:
            vuln = previous_vulns[vuln_key]
            
            changes.append({
                'change_type': 'removed',
                'category': 'vulnerability',
                'identifier': vuln_key,
                'details': {
                    'host': vuln.get('host'),
                    'port': vuln.get('port'),
                    'vulnerability_type': vuln.get('vulnerability_type'),
                    'severity': vuln.get('severity'),
                    'title': vuln.get('title')
                },
                'severity': 'low',
                'description': f"Vulnerability resolved: {vuln.get('title', vuln.get('vulnerability_type'))} "
                              f"on {vuln.get('host')}" + 
                              (f":{vuln.get('port')}" if vuln.get('port') else "")
            })
        
        return changes
    
    def _index_services(self, services: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Create index of services by host:port:protocol."""
        index = {}
        for service in services:
            key = f"{service.get('host')}:{service.get('port')}:{service.get('protocol', 'tcp')}"
            index[key] = service
        return index
    
    def _index_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Create index of vulnerabilities by unique identifier."""
        index = {}
        for vuln in vulnerabilities:
            # Create unique key based on host, port, and vulnerability type
            key_parts = [
                vuln.get('host', ''),
                str(vuln.get('port', '')),
                vuln.get('vulnerability_type', ''),
                vuln.get('title', '')
            ]
            key = hashlib.md5(':'.join(key_parts).encode()).hexdigest()
            index[key] = vuln
        return index
    
    def _calculate_service_severity(self, service: Dict[str, Any]) -> str:
        """Calculate severity level for new service discovery."""
        service_name = service.get('service_name', '').lower()
        port = service.get('port', 0)
        
        # High risk services
        high_risk_services = [
            'ftp', 'telnet', 'rlogin', 'ssh', 'mysql', 'postgresql',
            'mongodb', 'redis', 'elasticsearch', 'rdp', 'vnc'
        ]
        
        # Critical risk ports
        critical_ports = [21, 23, 513, 514, 3389, 5900, 6379, 27017, 9200]
        
        # Administrative/management services
        admin_services = ['ssh', 'rdp', 'vnc', 'webmin', 'cpanel']
        
        if any(risk_service in service_name for risk_service in high_risk_services):
            return 'high'
        elif port in critical_ports:
            return 'high'
        elif any(admin_service in service_name for admin_service in admin_services):
            return 'high'
        elif port in [80, 443, 8080, 8443]:  # Web services
            return 'medium'
        else:
            return 'medium'
    
    def summarize_changes(self, changes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create summary of detected changes."""
        summary = {
            'total_changes': len(changes),
            'by_type': {},
            'by_category': {},
            'by_severity': {},
            'critical_changes': [],
            'new_vulnerabilities': 0,
            'new_services': 0,
            'new_subdomains': 0
        }
        
        for change in changes:
            change_type = change.get('change_type', 'unknown')
            category = change.get('category', 'unknown')
            severity = change.get('severity', 'low')
            
            # Count by type
            summary['by_type'][change_type] = summary['by_type'].get(change_type, 0) + 1
            
            # Count by category
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
            
            # Count by severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Track specific change types
            if change_type == 'new':
                if category == 'vulnerability':
                    summary['new_vulnerabilities'] += 1
                elif category == 'service':
                    summary['new_services'] += 1
                elif category == 'subdomain':
                    summary['new_subdomains'] += 1
            
            # Track critical changes
            if severity in ['critical', 'high']:
                summary['critical_changes'].append({
                    'type': change_type,
                    'category': category,
                    'description': change.get('description', ''),
                    'severity': severity
                })
        
        return summary
    
    def get_change_trends(self, domain: str, days: int = 30) -> Dict[str, Any]:
        """Get change trends for a domain over specified days."""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT 
                    DATE(sd.created_at) as change_date,
                    sd.change_type,
                    sd.change_category,
                    COUNT(*) as change_count
                FROM scan_deltas sd
                JOIN scan_sessions ss ON sd.session_id = ss.id
                WHERE ss.domain = ? 
                AND sd.created_at >= datetime('now', '-{} days')
                GROUP BY DATE(sd.created_at), sd.change_type, sd.change_category
                ORDER BY change_date DESC
            """.format(days), (domain,))
            
            trends = cursor.fetchall()
        
        # Process trends data
        trend_data = {
            'domain': domain,
            'period_days': days,
            'daily_changes': {},
            'change_type_totals': {},
            'category_totals': {},
            'most_active_day': None,
            'total_changes': 0
        }
        
        for trend in trends:
            date = trend['change_date']
            change_type = trend['change_type']
            category = trend['change_category']
            count = trend['change_count']
            
            # Daily changes
            if date not in trend_data['daily_changes']:
                trend_data['daily_changes'][date] = 0
            trend_data['daily_changes'][date] += count
            
            # Type totals
            trend_data['change_type_totals'][change_type] = \
                trend_data['change_type_totals'].get(change_type, 0) + count
            
            # Category totals
            trend_data['category_totals'][category] = \
                trend_data['category_totals'].get(category, 0) + count
            
            trend_data['total_changes'] += count
        
        # Find most active day
        if trend_data['daily_changes']:
            trend_data['most_active_day'] = max(
                trend_data['daily_changes'].items(),
                key=lambda x: x[1]
            )
        
        return trend_data
    
    def get_delta_report(self, session_id: int) -> Dict[str, Any]:
        """Generate comprehensive delta report for a session."""
        changes = self.db.get_scan_deltas(session_id)
        session = self.db.get_scan_session(session_id)
        
        if not session:
            return {'error': 'Session not found'}
        
        # Convert stored changes to proper format
        formatted_changes = []
        for change in changes:
            details = {}
            if change.get('change_details'):
                try:
                    details = json.loads(change['change_details'])
                except json.JSONDecodeError:
                    details = {}
            
            formatted_changes.append({
                'change_type': change['change_type'],
                'category': change['change_category'],
                'identifier': change['item_identifier'],
                'details': details,
                'created_at': change['created_at']
            })
        
        summary = self.summarize_changes(formatted_changes)
        
        return {
            'session_id': session_id,
            'domain': session['domain'],
            'scan_type': session['scan_type'],
            'scan_start': session['start_time'],
            'changes': formatted_changes,
            'summary': summary,
            'recommendations': self._generate_recommendations(summary)
        }
    
    def _generate_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on change summary."""
        recommendations = []
        
        if summary['new_vulnerabilities'] > 0:
            recommendations.append(
                f"Review and remediate {summary['new_vulnerabilities']} new vulnerabilities"
            )
        
        if summary['new_services'] > 5:
            recommendations.append(
                "Large number of new services detected - review for unauthorized services"
            )
        
        if summary['new_subdomains'] > 10:
            recommendations.append(
                "Many new subdomains discovered - verify they are authorized"
            )
        
        critical_count = len(summary['critical_changes'])
        if critical_count > 0:
            recommendations.append(
                f"Immediate attention required for {critical_count} critical changes"
            )
        
        if summary['by_severity'].get('high', 0) > 3:
            recommendations.append(
                "Multiple high-severity changes detected - prioritize investigation"
            )
        
        if not recommendations:
            recommendations.append("No immediate action required based on detected changes")
        
        return recommendations