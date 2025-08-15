"""DNS record validation module for OpenEASD."""

import dns.resolver
import dns.exception
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class DNSAnalyzer:
    """Analyzes DNS records for security vulnerabilities."""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 30
    
    def dns_record_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Validate DNS records (A, AAAA, NS, MX, CNAME).
        
        Args:
            domain: Target domain to analyze
            
        Returns:
            Dictionary containing DNS analysis results
        """
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'records': {},
            'vulnerabilities': [],
            'risk_level': 'low'
        }
        
        record_types = ['A', 'AAAA', 'NS', 'MX', 'CNAME', 'TXT']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records = [str(rdata) for rdata in answers]
                results['records'][record_type] = records
                
                # Check for security issues
                self._check_record_security(record_type, records, results)
                
            except dns.resolver.NXDOMAIN:
                logger.info(f"No {record_type} record found for {domain}")
            except dns.resolver.NoAnswer:
                logger.info(f"No {record_type} answer for {domain}")
            except dns.exception.DNSException as e:
                logger.error(f"DNS error for {record_type} record: {e}")
                results['vulnerabilities'].append({
                    'type': 'dns_resolution_error',
                    'severity': 'medium',
                    'description': f"Failed to resolve {record_type} record",
                    'details': str(e)
                })
        
        # Determine overall risk level
        results['risk_level'] = self._calculate_risk_level(results['vulnerabilities'])
        
        return results
    
    def _check_record_security(self, record_type: str, records: List[str], 
                             results: Dict[str, Any]) -> None:
        """Check specific record types for security issues."""
        
        if record_type == 'A' or record_type == 'AAAA':
            self._check_ip_security(records, results)
        elif record_type == 'MX':
            self._check_mx_security(records, results)
        elif record_type == 'NS':
            self._check_ns_security(records, results)
        elif record_type == 'TXT':
            self._check_txt_security(records, results)
    
    def _check_ip_security(self, ip_records: List[str], results: Dict[str, Any]) -> None:
        """Check IP addresses for security issues."""
        for ip in ip_records:
            # Check for private/internal IPs exposed publicly
            if self._is_private_ip(ip):
                results['vulnerabilities'].append({
                    'type': 'private_ip_exposure',
                    'severity': 'high',
                    'description': f"Private IP address {ip} exposed in public DNS",
                    'remediation': 'Remove private IP addresses from public DNS records'
                })
    
    def _check_mx_security(self, mx_records: List[str], results: Dict[str, Any]) -> None:
        """Check MX records for security issues."""
        if not mx_records:
            results['vulnerabilities'].append({
                'type': 'missing_mx_record',
                'severity': 'medium',
                'description': 'No MX records found - email delivery may fail',
                'remediation': 'Configure proper MX records for email delivery'
            })
    
    def _check_ns_security(self, ns_records: List[str], results: Dict[str, Any]) -> None:
        """Check NS records for security issues."""
        if len(ns_records) < 2:
            results['vulnerabilities'].append({
                'type': 'insufficient_nameservers',
                'severity': 'medium',
                'description': 'Less than 2 nameservers configured - single point of failure',
                'remediation': 'Configure at least 2 nameservers for redundancy'
            })
    
    def _check_txt_security(self, txt_records: List[str], results: Dict[str, Any]) -> None:
        """Check TXT records for security configurations."""
        spf_found = False
        dmarc_found = False
        
        for record in txt_records:
            if record.startswith('v=spf1'):
                spf_found = True
            elif record.startswith('v=DMARC1'):
                dmarc_found = True
        
        if not spf_found:
            results['vulnerabilities'].append({
                'type': 'missing_spf_record',
                'severity': 'high',
                'description': 'No SPF record found - email spoofing possible',
                'remediation': 'Configure SPF record to prevent email spoofing'
            })
        
        if not dmarc_found:
            results['vulnerabilities'].append({
                'type': 'missing_dmarc_record',
                'severity': 'high',
                'description': 'No DMARC record found - email authentication weak',
                'remediation': 'Configure DMARC record for email authentication'
            })
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private."""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False
    
    def _calculate_risk_level(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level based on vulnerabilities."""
        if not vulnerabilities:
            return 'low'
        
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity = max(severity_scores.get(vuln['severity'], 1) 
                          for vuln in vulnerabilities)
        
        if max_severity >= 4:
            return 'critical'
        elif max_severity >= 3:
            return 'high'
        elif max_severity >= 2:
            return 'medium'
        else:
            return 'low'