"""SSL/TLS certificate validation module for OpenEASD."""

import ssl
import socket
import certifi
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class SSLChecker:
    """Validates SSL/TLS certificate configuration and security."""
    
    def __init__(self):
        self.timeout = 10
    
    def ssl_certificate_validation(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Check SSL/TLS configuration, expiry, and trust chain.
        
        Args:
            domain: Target domain to check
            port: Port to check (default 443)
            
        Returns:
            Dictionary containing SSL validation results
        """
        results = {
            'domain': domain,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'certificate_info': {},
            'vulnerabilities': [],
            'risk_level': 'low'
        }
        
        try:
            # Create SSL context with certificate verification
            context = ssl.create_default_context(cafile=certifi.where())
            
            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Extract certificate information
                    results['certificate_info'] = self._extract_cert_info(cert)
                    results['certificate_info']['cipher'] = cipher
                    results['certificate_info']['protocol'] = protocol
                    
                    # Check for vulnerabilities
                    self._check_certificate_security(cert, cipher, protocol, results)
                    
        except ssl.SSLError as e:
            logger.error(f"SSL error for {domain}:{port}: {e}")
            results['vulnerabilities'].append({
                'type': 'ssl_connection_error',
                'severity': 'high',
                'description': f"SSL connection failed: {str(e)}",
                'remediation': 'Check SSL certificate configuration and validity'
            })
        except socket.timeout:
            logger.error(f"Connection timeout for {domain}:{port}")
            results['vulnerabilities'].append({
                'type': 'connection_timeout',
                'severity': 'medium',
                'description': f"Connection timeout to {domain}:{port}",
                'remediation': 'Check if service is running and accessible'
            })
        except Exception as e:
            logger.error(f"Unexpected error checking SSL for {domain}:{port}: {e}")
            results['vulnerabilities'].append({
                'type': 'ssl_check_error',
                'severity': 'medium',
                'description': f"SSL check failed: {str(e)}",
                'remediation': 'Investigate SSL configuration issues'
            })
        
        # Determine overall risk level
        results['risk_level'] = self._calculate_risk_level(results['vulnerabilities'])
        
        return results
    
    def _extract_cert_info(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant information from certificate."""
        cert_info = {
            'subject': dict(x[0] for x in cert.get('subject', [])),
            'issuer': dict(x[0] for x in cert.get('issuer', [])),
            'serial_number': cert.get('serialNumber'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter'),
            'version': cert.get('version'),
            'subject_alt_names': []
        }
        
        # Extract Subject Alternative Names
        if 'subjectAltName' in cert:
            cert_info['subject_alt_names'] = [name[1] for name in cert['subjectAltName']]
        
        return cert_info
    
    def _check_certificate_security(self, cert: Dict[str, Any], cipher: tuple, 
                                  protocol: str, results: Dict[str, Any]) -> None:
        """Check certificate and connection for security issues."""
        
        # Check certificate expiry
        self._check_certificate_expiry(cert, results)
        
        # Check cipher strength
        self._check_cipher_strength(cipher, results)
        
        # Check protocol version
        self._check_protocol_version(protocol, results)
        
        # Check certificate chain issues
        self._check_certificate_chain(cert, results)
    
    def _check_certificate_expiry(self, cert: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Check if certificate is expired or expiring soon."""
        not_after_str = cert.get('notAfter')
        if not not_after_str:
            return
        
        try:
            # Parse certificate expiry date
            not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            now = datetime.utcnow()
            days_until_expiry = (not_after - now).days
            
            if days_until_expiry < 0:
                results['vulnerabilities'].append({
                    'type': 'expired_certificate',
                    'severity': 'critical',
                    'description': f"SSL certificate expired {abs(days_until_expiry)} days ago",
                    'remediation': 'Renew SSL certificate immediately'
                })
            elif days_until_expiry < 7:
                results['vulnerabilities'].append({
                    'type': 'certificate_expiring_soon',
                    'severity': 'high',
                    'description': f"SSL certificate expires in {days_until_expiry} days",
                    'remediation': 'Renew SSL certificate before expiry'
                })
            elif days_until_expiry < 30:
                results['vulnerabilities'].append({
                    'type': 'certificate_expiring_soon',
                    'severity': 'medium',
                    'description': f"SSL certificate expires in {days_until_expiry} days",
                    'remediation': 'Plan SSL certificate renewal'
                })
                
        except ValueError as e:
            logger.error(f"Error parsing certificate expiry date: {e}")
    
    def _check_cipher_strength(self, cipher: tuple, results: Dict[str, Any]) -> None:
        """Check cipher suite strength."""
        if not cipher:
            return
        
        cipher_name = cipher[0] if cipher else ''
        
        # Check for weak ciphers
        weak_ciphers = ['RC4', 'DES', 'NULL', 'EXPORT']
        for weak_cipher in weak_ciphers:
            if weak_cipher in cipher_name.upper():
                results['vulnerabilities'].append({
                    'type': 'weak_cipher',
                    'severity': 'high',
                    'description': f"Weak cipher suite detected: {cipher_name}",
                    'remediation': 'Configure strong cipher suites (AES-256, ChaCha20)'
                })
                break
        
        # Check key length
        if len(cipher) > 2:
            key_length = cipher[2]
            if key_length < 128:
                results['vulnerabilities'].append({
                    'type': 'weak_key_length',
                    'severity': 'high',
                    'description': f"Weak key length: {key_length} bits",
                    'remediation': 'Use cipher suites with at least 128-bit keys'
                })
    
    def _check_protocol_version(self, protocol: str, results: Dict[str, Any]) -> None:
        """Check TLS protocol version."""
        if not protocol:
            return
        
        # Check for deprecated protocols
        deprecated_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        if protocol in deprecated_protocols:
            results['vulnerabilities'].append({
                'type': 'deprecated_protocol',
                'severity': 'high',
                'description': f"Deprecated protocol version: {protocol}",
                'remediation': 'Disable deprecated protocols and use TLSv1.2 or TLSv1.3'
            })
    
    def _check_certificate_chain(self, cert: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Check certificate chain for common issues."""
        
        # Check if self-signed
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        
        if subject.get('commonName') == issuer.get('commonName'):
            results['vulnerabilities'].append({
                'type': 'self_signed_certificate',
                'severity': 'medium',
                'description': 'Certificate appears to be self-signed',
                'remediation': 'Use certificates from trusted Certificate Authorities'
            })
        
        # Check for missing common name
        if not subject.get('commonName'):
            results['vulnerabilities'].append({
                'type': 'missing_common_name',
                'severity': 'medium',
                'description': 'Certificate missing Common Name (CN)',
                'remediation': 'Ensure certificate has proper Common Name field'
            })
    
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