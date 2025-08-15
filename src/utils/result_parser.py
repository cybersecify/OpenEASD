"""Output standardization and result parsing utilities for OpenEASD."""

import json
import xml.etree.ElementTree as ET
import re
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import ipaddress
import logging

logger = logging.getLogger(__name__)


class ResultParser:
    """Standardizes output formats across different security tools."""
    
    def __init__(self):
        self.severity_mapping = {
            'info': 'low',
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        }
    
    def parse_subfinder_output(self, output: str, domain: str) -> List[Dict[str, Any]]:
        """Parse Subfinder JSON output to standard format."""
        subdomains = []
        
        try:
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        subdomain = {
                            'subdomain': data.get('host', ''),
                            'source': data.get('source', 'subfinder'),
                            'ip_address': data.get('ip', ''),
                            'discovered_at': datetime.utcnow().isoformat(),
                            'parent_domain': domain,
                            'tool': 'subfinder'
                        }
                        
                        # Validate subdomain format
                        if self._is_valid_subdomain(subdomain['subdomain']):
                            subdomains.append(subdomain)
                            
                    except json.JSONDecodeError:
                        # Handle plain text output
                        subdomain_name = line.strip()
                        if self._is_valid_subdomain(subdomain_name):
                            subdomains.append({
                                'subdomain': subdomain_name,
                                'source': 'subfinder',
                                'ip_address': '',
                                'discovered_at': datetime.utcnow().isoformat(),
                                'parent_domain': domain,
                                'tool': 'subfinder'
                            })
                            
        except Exception as e:
            logger.error(f"Error parsing Subfinder output: {e}")
        
        return subdomains
    
    def parse_naabu_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Naabu JSON output to standard format."""
        services = []
        
        try:
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        service = {
                            'host': data.get('host', ''),
                            'port': data.get('port', 0),
                            'protocol': data.get('protocol', 'tcp'),
                            'state': 'open',
                            'service_name': '',
                            'version': '',
                            'discovered_at': datetime.utcnow().isoformat(),
                            'tool': 'naabu',
                            'risk_level': self._assess_port_risk(data.get('port', 0))
                        }
                        
                        services.append(service)
                        
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.error(f"Error parsing Naabu output: {e}")
        
        return services
    
    def parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output to standard format."""
        services = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall('host'):
                # Get host IP
                address_elem = host.find('address')
                host_ip = address_elem.get('addr') if address_elem is not None else ''
                
                # Parse ports
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_id = int(port.get('portid', 0))
                        protocol = port.get('protocol', 'tcp')
                        
                        # Get state
                        state_elem = port.find('state')
                        state = state_elem.get('state') if state_elem is not None else 'unknown'
                        
                        # Get service info
                        service_elem = port.find('service')
                        service_name = ''
                        version = ''
                        
                        if service_elem is not None:
                            service_name = service_elem.get('name', '')
                            version = service_elem.get('version', '')
                            product = service_elem.get('product', '')
                            if product:
                                version = f"{product} {version}".strip()
                        
                        service = {
                            'host': host_ip,
                            'port': port_id,
                            'protocol': protocol,
                            'state': state,
                            'service_name': service_name,
                            'version': version,
                            'discovered_at': datetime.utcnow().isoformat(),
                            'tool': 'nmap',
                            'risk_level': self._assess_service_risk(service_name, port_id)
                        }
                        
                        services.append(service)
                        
        except ET.ParseError as e:
            logger.error(f"Error parsing Nmap XML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing Nmap output: {e}")
        
        return services
    
    def parse_nuclei_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output to standard format."""
        vulnerabilities = []
        
        try:
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        
                        # Extract basic info
                        info = data.get('info', {})
                        
                        vulnerability = {
                            'host': data.get('host', ''),
                            'port': self._extract_port_from_url(data.get('matched-at', '')),
                            'vulnerability_type': data.get('templateID', ''),
                            'severity': self._normalize_severity(info.get('severity', 'info')),
                            'title': info.get('name', ''),
                            'description': info.get('description', ''),
                            'remediation': info.get('remediation', ''),
                            'reference': info.get('reference', []),
                            'classification': info.get('classification', {}),
                            'matched_at': data.get('matched-at', ''),
                            'template_id': data.get('templateID', ''),
                            'discovered_at': datetime.utcnow().isoformat(),
                            'tool': 'nuclei',
                            'confidence': 'medium',
                            'cvss_score': self._extract_cvss_score(info.get('classification', {})),
                            'cve_id': self._extract_cve_id(info.get('classification', {})),
                            'mitre_technique': self._extract_mitre_technique(info.get('classification', {}))
                        }
                        
                        vulnerabilities.append(vulnerability)
                        
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.error(f"Error parsing Nuclei output: {e}")
        
        return vulnerabilities
    
    def parse_custom_dns_output(self, dns_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse custom DNS analysis results to standard format."""
        vulnerabilities = []
        
        for vuln in dns_results.get('vulnerabilities', []):
            vulnerability = {
                'host': dns_results.get('domain', ''),
                'port': None,
                'vulnerability_type': vuln.get('type', 'dns_misconfiguration'),
                'severity': vuln.get('severity', 'medium'),
                'title': vuln.get('type', '').replace('_', ' ').title(),
                'description': vuln.get('description', ''),
                'remediation': vuln.get('remediation', ''),
                'discovered_at': datetime.utcnow().isoformat(),
                'tool': 'dns_analyzer',
                'confidence': 'high',
                'mitre_technique': vuln.get('mitre_technique', ''),
                'details': vuln.get('details', {})
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def parse_ssl_analysis(self, ssl_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse SSL analysis results to standard format."""
        vulnerabilities = []
        
        for vuln in ssl_results.get('vulnerabilities', []):
            vulnerability = {
                'host': ssl_results.get('domain', ''),
                'port': ssl_results.get('port', 443),
                'vulnerability_type': vuln.get('type', 'ssl_misconfiguration'),
                'severity': vuln.get('severity', 'medium'),
                'title': vuln.get('type', '').replace('_', ' ').title(),
                'description': vuln.get('description', ''),
                'remediation': vuln.get('remediation', ''),
                'discovered_at': datetime.utcnow().isoformat(),
                'tool': 'ssl_checker',
                'confidence': 'high',
                'certificate_info': ssl_results.get('certificate_info', {})
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def parse_email_security(self, email_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse email security analysis to standard format."""
        vulnerabilities = []
        
        for vuln in email_results.get('vulnerabilities', []):
            vulnerability = {
                'host': email_results.get('domain', ''),
                'port': None,
                'vulnerability_type': vuln.get('type', 'email_security'),
                'severity': vuln.get('severity', 'medium'),
                'title': vuln.get('type', '').replace('_', ' ').title(),
                'description': vuln.get('description', ''),
                'remediation': vuln.get('remediation', ''),
                'discovered_at': datetime.utcnow().isoformat(),
                'tool': 'email_security',
                'confidence': 'high',
                'mitre_technique': vuln.get('mitre_technique', 'T1566.001')
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def standardize_all_results(self, raw_results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Standardize results from all tools into common format."""
        standardized = {
            'subdomains': [],
            'services': [],
            'vulnerabilities': []
        }
        
        # Parse tool outputs
        if 'subfinder' in raw_results:
            subfinder_data = raw_results['subfinder']
            if isinstance(subfinder_data, dict) and 'stdout' in subfinder_data:
                domain = subfinder_data.get('domain', '')
                standardized['subdomains'].extend(
                    self.parse_subfinder_output(subfinder_data['stdout'], domain)
                )
        
        if 'naabu' in raw_results:
            naabu_data = raw_results['naabu']
            if isinstance(naabu_data, dict) and 'stdout' in naabu_data:
                standardized['services'].extend(
                    self.parse_naabu_output(naabu_data['stdout'])
                )
        
        if 'nmap' in raw_results:
            nmap_data = raw_results['nmap']
            if isinstance(nmap_data, dict) and 'stdout' in nmap_data:
                standardized['services'].extend(
                    self.parse_nmap_xml(nmap_data['stdout'])
                )
        
        if 'nuclei' in raw_results:
            nuclei_data = raw_results['nuclei']
            if isinstance(nuclei_data, dict) and 'stdout' in nuclei_data:
                standardized['vulnerabilities'].extend(
                    self.parse_nuclei_output(nuclei_data['stdout'])
                )
        
        # Parse custom module results
        if 'dns_analysis' in raw_results:
            standardized['vulnerabilities'].extend(
                self.parse_custom_dns_output(raw_results['dns_analysis'])
            )
        
        if 'ssl_analysis' in raw_results:
            standardized['vulnerabilities'].extend(
                self.parse_ssl_analysis(raw_results['ssl_analysis'])
            )
        
        if 'email_security' in raw_results:
            standardized['vulnerabilities'].extend(
                self.parse_email_security(raw_results['email_security'])
            )
        
        return standardized
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format."""
        if not subdomain or len(subdomain) > 253:
            return False
        
        # Basic regex for domain validation
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, subdomain))
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _assess_port_risk(self, port: int) -> str:
        """Assess risk level based on port number."""
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 1521, 3389, 5432, 5900, 6379, 27017]
        medium_risk_ports = [22, 53, 80, 110, 143, 443, 993, 995, 3306, 5060, 8080, 8443]
        
        if port in high_risk_ports:
            return 'high'
        elif port in medium_risk_ports:
            return 'medium'
        else:
            return 'low'
    
    def _assess_service_risk(self, service_name: str, port: int) -> str:
        """Assess risk level based on service name and port."""
        service_name = service_name.lower()
        
        high_risk_services = ['ftp', 'telnet', 'rlogin', 'mysql', 'postgresql', 'redis', 'mongodb']
        medium_risk_services = ['ssh', 'http', 'https', 'smtp', 'pop3', 'imap']
        
        if any(risk_service in service_name for risk_service in high_risk_services):
            return 'high'
        elif any(risk_service in service_name for risk_service in medium_risk_services):
            return 'medium'
        else:
            return self._assess_port_risk(port)
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity levels across tools."""
        severity_lower = severity.lower()
        return self.severity_mapping.get(severity_lower, 'medium')
    
    def _extract_port_from_url(self, url: str) -> Optional[int]:
        """Extract port number from URL."""
        try:
            if '://' in url:
                # Parse URL to extract port
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.port:
                    return parsed.port
                elif parsed.scheme == 'https':
                    return 443
                elif parsed.scheme == 'http':
                    return 80
        except Exception:
            pass
        return None
    
    def _extract_cvss_score(self, classification: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from classification."""
        cvss_metrics = classification.get('cvss-metrics', '')
        if cvss_metrics:
            # Simple regex to extract CVSS score
            match = re.search(r'CVSS:3\.\d/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]/E:[XUPFH]/RL:[XOTWU]/RC:[XURC]/(\d+\.\d+)', cvss_metrics)
            if match:
                return float(match.group(1))
        return None
    
    def _extract_cve_id(self, classification: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from classification."""
        cve_id = classification.get('cve-id')
        if cve_id:
            if isinstance(cve_id, list):
                return cve_id[0] if cve_id else None
            return str(cve_id)
        return None
    
    def _extract_mitre_technique(self, classification: Dict[str, Any]) -> Optional[str]:
        """Extract MITRE ATT&CK technique from classification."""
        cwe_id = classification.get('cwe-id')
        if cwe_id:
            # Simple mapping of common CWEs to MITRE techniques
            cwe_to_mitre = {
                'CWE-79': 'T1189',   # XSS -> Drive-by Compromise
                'CWE-89': 'T1190',   # SQL Injection -> Exploit Public-Facing Application
                'CWE-22': 'T1083',   # Path Traversal -> File and Directory Discovery
                'CWE-352': 'T1189',  # CSRF -> Drive-by Compromise
                'CWE-200': 'T1083',  # Information Exposure -> File and Directory Discovery
            }
            
            if isinstance(cwe_id, list):
                cwe_id = cwe_id[0] if cwe_id else ''
            
            return cwe_to_mitre.get(str(cwe_id), 'T1190')
        
        return 'T1190'  # Default to Exploit Public-Facing Application
    
    def generate_summary_report(self, standardized_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate summary report from standardized results."""
        subdomains = standardized_results.get('subdomains', [])
        services = standardized_results.get('services', [])
        vulnerabilities = standardized_results.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by tool
        tool_counts = {}
        for vuln in vulnerabilities:
            tool = vuln.get('tool', 'unknown')
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        # Top vulnerability types
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        top_vuln_types = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'summary': {
                'total_subdomains': len(subdomains),
                'total_services': len(services),
                'total_vulnerabilities': len(vulnerabilities),
                'unique_hosts': len(set(vuln.get('host', '') for vuln in vulnerabilities)),
            },
            'severity_breakdown': severity_counts,
            'tool_breakdown': tool_counts,
            'top_vulnerability_types': top_vuln_types,
            'risk_score': self._calculate_risk_score(severity_counts),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate overall risk score based on vulnerability counts."""
        weights = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        
        score = sum(count * weights.get(severity, 1) 
                   for severity, count in severity_counts.items())
        
        # Normalize to 0-100 scale
        return min(100, score)