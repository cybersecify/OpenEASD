"""MITRE ATT&CK framework mapping utilities for OpenEASD."""

import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class MITREMapper:
    """Maps vulnerabilities and findings to MITRE ATT&CK framework."""
    
    def __init__(self):
        self.technique_mappings = self._load_technique_mappings()
        self.tactic_mappings = self._load_tactic_mappings()
    
    def _load_technique_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK technique mappings."""
        return {
            # Reconnaissance (TA0043)
            'T1590': {
                'name': 'Gather Victim Network Information',
                'tactic': 'reconnaissance',
                'description': 'Adversaries may gather information about the victim\'s networks',
                'detection': 'Monitor for suspicious network reconnaissance activity'
            },
            'T1590.001': {
                'name': 'Domain Properties',
                'tactic': 'reconnaissance', 
                'parent': 'T1590',
                'description': 'Adversaries may gather information about domain properties',
                'detection': 'Monitor DNS queries and domain enumeration attempts'
            },
            'T1590.005': {
                'name': 'IP Addresses',
                'tactic': 'reconnaissance',
                'parent': 'T1590',
                'description': 'Adversaries may gather IP addresses',
                'detection': 'Monitor for IP address enumeration and scanning'
            },
            'T1595': {
                'name': 'Active Scanning',
                'tactic': 'reconnaissance',
                'description': 'Adversaries may execute active reconnaissance scans',
                'detection': 'Monitor for port scans and service enumeration'
            },
            'T1595.001': {
                'name': 'Scanning IP Blocks',
                'tactic': 'reconnaissance',
                'parent': 'T1595',
                'description': 'Adversaries may scan victim IP blocks',
                'detection': 'Monitor for systematic IP scanning patterns'
            },
            'T1595.002': {
                'name': 'Vulnerability Scanning',
                'tactic': 'reconnaissance',
                'parent': 'T1595',
                'description': 'Adversaries may scan for vulnerabilities',
                'detection': 'Monitor for vulnerability scanning tools and patterns'
            },
            'T1596': {
                'name': 'Search Open Websites/Domains',
                'tactic': 'reconnaissance',
                'description': 'Adversaries may search freely available websites',
                'detection': 'Monitor for automated searches and scraping'
            },
            
            # Resource Development (TA0042)
            'T1583': {
                'name': 'Acquire Infrastructure',
                'tactic': 'resource-development',
                'description': 'Adversaries may buy or steal infrastructure',
                'detection': 'Monitor for suspicious domain registrations'
            },
            'T1583.001': {
                'name': 'Domains',
                'tactic': 'resource-development',
                'parent': 'T1583',
                'description': 'Adversaries may acquire domains for operations',
                'detection': 'Monitor for typosquatting and suspicious domains'
            },
            
            # Initial Access (TA0001)
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'tactic': 'initial-access',
                'description': 'Adversaries may attempt to exploit vulnerabilities',
                'detection': 'Monitor web application logs for exploitation attempts'
            },
            'T1133': {
                'name': 'External Remote Services',
                'tactic': 'initial-access',
                'description': 'Adversaries may leverage external remote services',
                'detection': 'Monitor remote access service logs'
            },
            'T1566': {
                'name': 'Phishing',
                'tactic': 'initial-access',
                'description': 'Adversaries may send phishing messages',
                'detection': 'Monitor email for phishing indicators'
            },
            'T1566.001': {
                'name': 'Spearphishing Attachment',
                'tactic': 'initial-access',
                'parent': 'T1566',
                'description': 'Adversaries may send spearphishing emails with malicious attachments',
                'detection': 'Monitor email attachments and SPF/DKIM/DMARC failures'
            },
            
            # Execution (TA0002)
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'tactic': 'execution',
                'description': 'Adversaries may abuse command and script interpreters',
                'detection': 'Monitor command-line activity'
            },
            'T1203': {
                'name': 'Exploitation for Client Execution',
                'tactic': 'execution',
                'description': 'Adversaries may exploit software vulnerabilities',
                'detection': 'Monitor for exploitation attempts'
            },
            
            # Discovery (TA0007)
            'T1046': {
                'name': 'Network Service Scanning',
                'tactic': 'discovery',
                'description': 'Adversaries may attempt to get a listing of services',
                'detection': 'Monitor for port scanning activity'
            },
            'T1083': {
                'name': 'File and Directory Discovery',
                'tactic': 'discovery',
                'description': 'Adversaries may enumerate files and directories',
                'detection': 'Monitor file system access patterns'
            },
            'T1087': {
                'name': 'Account Discovery',
                'tactic': 'discovery',
                'description': 'Adversaries may attempt to get account names',
                'detection': 'Monitor for account enumeration'
            },
            
            # Lateral Movement (TA0008)
            'T1021': {
                'name': 'Remote Services',
                'tactic': 'lateral-movement',
                'description': 'Adversaries may use remote services to move laterally',
                'detection': 'Monitor remote service connections'
            },
            
            # Collection (TA0009)
            'T1005': {
                'name': 'Data from Local System',
                'tactic': 'collection',
                'description': 'Adversaries may search local system sources',
                'detection': 'Monitor file access patterns'
            },
            
            # Command and Control (TA0011)
            'T1071': {
                'name': 'Application Layer Protocol',
                'tactic': 'command-and-control',
                'description': 'Adversaries may communicate using application layer protocols',
                'detection': 'Monitor network traffic for C2 indicators'
            },
            'T1071.001': {
                'name': 'Web Protocols',
                'tactic': 'command-and-control',
                'parent': 'T1071',
                'description': 'Adversaries may communicate using web protocols',
                'detection': 'Monitor HTTP/HTTPS traffic patterns'
            },
            
            # Impact (TA0040)
            'T1496': {
                'name': 'Resource Hijacking',
                'tactic': 'impact',
                'description': 'Adversaries may leverage resources for cryptomining',
                'detection': 'Monitor for unauthorized resource usage'
            }
        }
    
    def _load_tactic_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK tactic mappings."""
        return {
            'reconnaissance': {
                'id': 'TA0043',
                'name': 'Reconnaissance',
                'description': 'The adversary is trying to gather information they can use to plan future operations.'
            },
            'resource-development': {
                'id': 'TA0042',
                'name': 'Resource Development',
                'description': 'The adversary is trying to establish resources they can use to support operations.'
            },
            'initial-access': {
                'id': 'TA0001',
                'name': 'Initial Access',
                'description': 'The adversary is trying to get into your network.'
            },
            'execution': {
                'id': 'TA0002',
                'name': 'Execution',
                'description': 'The adversary is trying to run malicious code.'
            },
            'persistence': {
                'id': 'TA0003',
                'name': 'Persistence',
                'description': 'The adversary is trying to maintain their foothold.'
            },
            'privilege-escalation': {
                'id': 'TA0004',
                'name': 'Privilege Escalation',
                'description': 'The adversary is trying to gain higher-level permissions.'
            },
            'defense-evasion': {
                'id': 'TA0005',
                'name': 'Defense Evasion',
                'description': 'The adversary is trying to avoid being detected.'
            },
            'credential-access': {
                'id': 'TA0006',
                'name': 'Credential Access',
                'description': 'The adversary is trying to steal account names and passwords.'
            },
            'discovery': {
                'id': 'TA0007',
                'name': 'Discovery',
                'description': 'The adversary is trying to figure out your environment.'
            },
            'lateral-movement': {
                'id': 'TA0008',
                'name': 'Lateral Movement',
                'description': 'The adversary is trying to move through your environment.'
            },
            'collection': {
                'id': 'TA0009',
                'name': 'Collection',
                'description': 'The adversary is trying to gather data of interest.'
            },
            'command-and-control': {
                'id': 'TA0011',
                'name': 'Command and Control',
                'description': 'The adversary is trying to communicate with compromised systems.'
            },
            'exfiltration': {
                'id': 'TA0010',
                'name': 'Exfiltration',
                'description': 'The adversary is trying to steal data.'
            },
            'impact': {
                'id': 'TA0040',
                'name': 'Impact',
                'description': 'The adversary is trying to manipulate, interrupt, or destroy systems and data.'
            }
        }
    
    def map_vulnerability_to_technique(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Map a vulnerability to appropriate MITRE ATT&CK technique."""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        service_name = vulnerability.get('service_name', '').lower()
        port = vulnerability.get('port', 0)
        description = vulnerability.get('description', '').lower()
        
        # Direct mapping based on vulnerability type
        vuln_mappings = {
            'exposed_database': 'T1190',
            'default_credentials': 'T1078',
            'admin_panel_no_auth': 'T1190',
            'missing_spf_record': 'T1566.001',
            'missing_dmarc_record': 'T1566.001',
            'expired_ssl_certificate': 'T1190',
            'weak_ssl_configuration': 'T1190',
            'insecure_ftp_service': 'T1021',
            'missing_security_headers': 'T1190',
            'sql_injection': 'T1190',
            'xss': 'T1189',
            'csrf': 'T1189',
            'directory_traversal': 'T1083',
            'information_disclosure': 'T1083',
            'remote_code_execution': 'T1190',
            'authentication_bypass': 'T1078',
            'privilege_escalation': 'T1068',
            'cybersquatting_domains': 'T1583.001',
            'typosquatting': 'T1583.001'
        }
        
        # Check direct mappings
        for vuln_pattern, technique in vuln_mappings.items():
            if vuln_pattern in vuln_type or vuln_pattern in description:
                return technique
        
        # Service-based mappings
        service_mappings = {
            'ftp': 'T1021',
            'telnet': 'T1021',
            'ssh': 'T1021',
            'rdp': 'T1021',
            'vnc': 'T1021',
            'mysql': 'T1190',
            'postgresql': 'T1190',
            'mongodb': 'T1190',
            'redis': 'T1190',
            'elasticsearch': 'T1190',
            'http': 'T1190',
            'https': 'T1190'
        }
        
        for service, technique in service_mappings.items():
            if service in service_name:
                return technique
        
        # Port-based mappings
        port_mappings = {
            21: 'T1021',    # FTP
            22: 'T1021',    # SSH
            23: 'T1021',    # Telnet
            80: 'T1190',    # HTTP
            443: 'T1190',   # HTTPS
            1433: 'T1190',  # MSSQL
            3306: 'T1190',  # MySQL
            3389: 'T1021',  # RDP
            5432: 'T1190',  # PostgreSQL
            5900: 'T1021',  # VNC
            6379: 'T1190',  # Redis
            27017: 'T1190', # MongoDB
        }
        
        if port in port_mappings:
            return port_mappings[port]
        
        # Default mapping based on context
        if 'network' in description or 'port' in description:
            return 'T1046'  # Network Service Scanning
        elif 'web' in description or 'http' in description:
            return 'T1190'  # Exploit Public-Facing Application
        elif 'dns' in description:
            return 'T1590.001'  # Domain Properties
        elif 'email' in description:
            return 'T1566.001'  # Spearphishing
        
        return 'T1190'  # Default to Exploit Public-Facing Application
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a MITRE ATT&CK technique."""
        return self.technique_mappings.get(technique_id)
    
    def get_tactic_info(self, tactic_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a MITRE ATT&CK tactic."""
        return self.tactic_mappings.get(tactic_name)
    
    def enrich_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich vulnerabilities with MITRE ATT&CK mappings."""
        enriched = []
        
        for vuln in vulnerabilities:
            enriched_vuln = vuln.copy()
            
            # Get or assign MITRE technique
            technique_id = vuln.get('mitre_technique')
            if not technique_id:
                technique_id = self.map_vulnerability_to_technique(vuln)
                enriched_vuln['mitre_technique'] = technique_id
            
            # Add technique details
            technique_info = self.get_technique_info(technique_id)
            if technique_info:
                enriched_vuln['mitre_technique_name'] = technique_info.get('name', '')
                enriched_vuln['mitre_tactic'] = technique_info.get('tactic', '')
                enriched_vuln['mitre_description'] = technique_info.get('description', '')
                enriched_vuln['mitre_detection'] = technique_info.get('detection', '')
                
                # Add tactic information
                tactic_info = self.get_tactic_info(technique_info.get('tactic', ''))
                if tactic_info:
                    enriched_vuln['mitre_tactic_id'] = tactic_info.get('id', '')
                    enriched_vuln['mitre_tactic_name'] = tactic_info.get('name', '')
            
            enriched.append(enriched_vuln)
        
        return enriched
    
    def generate_attack_path_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate potential attack path analysis based on vulnerabilities."""
        technique_counts = {}
        tactic_counts = {}
        attack_chains = []
        
        # Count techniques and tactics
        for vuln in vulnerabilities:
            technique_id = vuln.get('mitre_technique')
            if technique_id:
                technique_counts[technique_id] = technique_counts.get(technique_id, 0) + 1
                
                technique_info = self.get_technique_info(technique_id)
                if technique_info:
                    tactic = technique_info.get('tactic')
                    if tactic:
                        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        # Identify potential attack chains
        if 'reconnaissance' in tactic_counts and 'initial-access' in tactic_counts:
            attack_chains.append({
                'name': 'Reconnaissance to Initial Access',
                'description': 'Adversary can gather information and exploit vulnerabilities',
                'tactics': ['reconnaissance', 'initial-access'],
                'risk_level': 'high'
            })
        
        if 'initial-access' in tactic_counts and 'discovery' in tactic_counts:
            attack_chains.append({
                'name': 'Initial Access to Discovery',
                'description': 'Adversary can gain access and enumerate environment',
                'tactics': ['initial-access', 'discovery'],
                'risk_level': 'high'
            })
        
        if 'discovery' in tactic_counts and 'lateral-movement' in tactic_counts:
            attack_chains.append({
                'name': 'Discovery to Lateral Movement',
                'description': 'Adversary can discover and move through network',
                'tactics': ['discovery', 'lateral-movement'],
                'risk_level': 'critical'
            })
        
        # Calculate coverage
        total_tactics = len(self.tactic_mappings)
        covered_tactics = len(tactic_counts)
        coverage_percentage = (covered_tactics / total_tactics) * 100
        
        return {
            'technique_counts': technique_counts,
            'tactic_counts': tactic_counts,
            'attack_chains': attack_chains,
            'tactic_coverage': {
                'covered_tactics': covered_tactics,
                'total_tactics': total_tactics,
                'coverage_percentage': coverage_percentage
            },
            'risk_assessment': self._assess_attack_risk(tactic_counts, attack_chains)
        }
    
    def _assess_attack_risk(self, tactic_counts: Dict[str, int], 
                           attack_chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall attack risk based on MITRE mappings."""
        risk_score = 0
        risk_factors = []
        
        # High-risk tactics
        high_risk_tactics = ['initial-access', 'persistence', 'privilege-escalation', 'lateral-movement']
        for tactic in high_risk_tactics:
            if tactic in tactic_counts:
                risk_score += tactic_counts[tactic] * 3
                risk_factors.append(f"Vulnerabilities enable {tactic.replace('-', ' ')}")
        
        # Medium-risk tactics
        medium_risk_tactics = ['reconnaissance', 'discovery', 'collection', 'command-and-control']
        for tactic in medium_risk_tactics:
            if tactic in tactic_counts:
                risk_score += tactic_counts[tactic] * 2
        
        # Attack chain multiplier
        if len(attack_chains) > 0:
            risk_score *= (1 + len(attack_chains) * 0.2)
            risk_factors.append(f"Multiple attack chains possible ({len(attack_chains)})")
        
        # Determine risk level
        if risk_score >= 20:
            risk_level = 'critical'
        elif risk_score >= 10:
            risk_level = 'high'
        elif risk_score >= 5:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'recommendations': self._generate_mitre_recommendations(tactic_counts)
        }
    
    def _generate_mitre_recommendations(self, tactic_counts: Dict[str, int]) -> List[str]:
        """Generate recommendations based on MITRE tactic coverage."""
        recommendations = []
        
        if 'reconnaissance' in tactic_counts:
            recommendations.append("Implement network monitoring to detect reconnaissance activity")
        
        if 'initial-access' in tactic_counts:
            recommendations.append("Strengthen perimeter defenses and patch public-facing applications")
        
        if 'persistence' in tactic_counts:
            recommendations.append("Monitor for unauthorized persistence mechanisms")
        
        if 'privilege-escalation' in tactic_counts:
            recommendations.append("Implement least-privilege access controls")
        
        if 'lateral-movement' in tactic_counts:
            recommendations.append("Segment networks and monitor east-west traffic")
        
        if 'discovery' in tactic_counts:
            recommendations.append("Monitor for unusual enumeration activity")
        
        if len(tactic_counts) > 3:
            recommendations.append("Implement comprehensive security monitoring across all attack vectors")
        
        return recommendations
    
    def export_mitre_report(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Export comprehensive MITRE ATT&CK mapping report."""
        enriched_vulnerabilities = self.enrich_vulnerabilities(vulnerabilities)
        attack_analysis = self.generate_attack_path_analysis(enriched_vulnerabilities)
        
        return {
            'report_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'total_vulnerabilities': len(enriched_vulnerabilities),
                'mitre_version': '12.1',  # ATT&CK version
                'framework': 'MITRE ATT&CK Enterprise'
            },
            'enriched_vulnerabilities': enriched_vulnerabilities,
            'attack_analysis': attack_analysis,
            'technique_details': {
                technique_id: self.get_technique_info(technique_id)
                for technique_id in attack_analysis['technique_counts'].keys()
                if self.get_technique_info(technique_id)
            },
            'tactic_details': {
                tactic: self.get_tactic_info(tactic)
                for tactic in attack_analysis['tactic_counts'].keys()
                if self.get_tactic_info(tactic)
            }
        }