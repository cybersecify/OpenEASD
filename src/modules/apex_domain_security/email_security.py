"""Email security validation module for SPF/DKIM/DMARC records."""

import dns.resolver
import dns.exception
from typing import Dict, List, Any, Optional
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)


class EmailSecurity:
    """Validates email security records (SPF, DKIM, DMARC)."""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 30
    
    def spf_dmarc_checker(self, domain: str) -> Dict[str, Any]:
        """
        Validate email security records (SPF, DKIM, DMARC).
        
        Args:
            domain: Target domain to check
            
        Returns:
            Dictionary containing email security analysis results
        """
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'spf': {},
            'dmarc': {},
            'dkim': {},
            'vulnerabilities': [],
            'risk_level': 'low'
        }
        
        # Check SPF record
        results['spf'] = self._check_spf_record(domain)
        
        # Check DMARC record
        results['dmarc'] = self._check_dmarc_record(domain)
        
        # Check common DKIM selectors
        results['dkim'] = self._check_dkim_records(domain)
        
        # Analyze findings for vulnerabilities
        self._analyze_email_security(results)
        
        # Determine overall risk level
        results['risk_level'] = self._calculate_risk_level(results['vulnerabilities'])
        
        return results
    
    def _check_spf_record(self, domain: str) -> Dict[str, Any]:
        """Check SPF record for domain."""
        spf_result = {
            'exists': False,
            'record': '',
            'mechanisms': [],
            'issues': []
        }
        
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith('v=spf1'):
                    spf_result['exists'] = True
                    spf_result['record'] = record
                    spf_result['mechanisms'] = self._parse_spf_mechanisms(record)
                    spf_result['issues'] = self._validate_spf_record(record)
                    break
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.info(f"No TXT records found for {domain}")
        except dns.exception.DNSException as e:
            logger.error(f"DNS error checking SPF for {domain}: {e}")
            spf_result['issues'].append(f"DNS resolution error: {e}")
        
        return spf_result
    
    def _check_dmarc_record(self, domain: str) -> Dict[str, Any]:
        """Check DMARC record for domain."""
        dmarc_result = {
            'exists': False,
            'record': '',
            'policy': '',
            'subdomain_policy': '',
            'issues': []
        }
        
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith('v=DMARC1'):
                    dmarc_result['exists'] = True
                    dmarc_result['record'] = record
                    
                    # Parse DMARC policy
                    policy_match = re.search(r'p=(\w+)', record)
                    if policy_match:
                        dmarc_result['policy'] = policy_match.group(1)
                    
                    # Parse subdomain policy
                    sp_match = re.search(r'sp=(\w+)', record)
                    if sp_match:
                        dmarc_result['subdomain_policy'] = sp_match.group(1)
                    
                    dmarc_result['issues'] = self._validate_dmarc_record(record)
                    break
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.info(f"No DMARC record found for {domain}")
        except dns.exception.DNSException as e:
            logger.error(f"DNS error checking DMARC for {domain}: {e}")
            dmarc_result['issues'].append(f"DNS resolution error: {e}")
        
        return dmarc_result
    
    def _check_dkim_records(self, domain: str) -> Dict[str, Any]:
        """Check common DKIM selectors for domain."""
        dkim_result = {
            'selectors_found': [],
            'selectors_checked': [],
            'issues': []
        }
        
        # Common DKIM selectors to check
        common_selectors = [
            'default', 'google', 'k1', 'mail', 'dkim', 'selector1', 
            'selector2', 's1', 's2', 'mx', 'email'
        ]
        
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_result['selectors_checked'].append(selector)
            
            try:
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    record = str(rdata).strip('"')
                    if 'k=' in record or 'p=' in record:  # DKIM key indicators
                        dkim_result['selectors_found'].append({
                            'selector': selector,
                            'record': record,
                            'domain': dkim_domain
                        })
                        break
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException as e:
                logger.error(f"DNS error checking DKIM {dkim_domain}: {e}")
                continue
        
        return dkim_result
    
    def _parse_spf_mechanisms(self, spf_record: str) -> List[str]:
        """Parse SPF mechanisms from record."""
        mechanisms = []
        parts = spf_record.split()
        
        for part in parts[1:]:  # Skip 'v=spf1'
            if part.startswith(('include:', 'a:', 'mx:', 'ip4:', 'ip6:', 'exists:')):
                mechanisms.append(part)
            elif part in ['a', 'mx', 'ptr']:
                mechanisms.append(part)
            elif part in ['~all', '-all', '+all', '?all']:
                mechanisms.append(part)
        
        return mechanisms
    
    def _validate_spf_record(self, spf_record: str) -> List[str]:
        """Validate SPF record for common issues."""
        issues = []
        
        # Check for too many DNS lookups
        dns_lookup_mechanisms = ['include:', 'a:', 'mx:', 'exists:', 'redirect:']
        dns_lookups = sum(1 for part in spf_record.split() 
                         for mechanism in dns_lookup_mechanisms 
                         if part.startswith(mechanism))
        
        if dns_lookups > 10:
            issues.append(f"Too many DNS lookups ({dns_lookups}/10) - may cause SPF validation failures")
        
        # Check for missing 'all' mechanism
        if not any(part.endswith('all') for part in spf_record.split()):
            issues.append("Missing 'all' mechanism - SPF policy incomplete")
        
        # Check for permissive 'all' mechanism
        if '+all' in spf_record:
            issues.append("Permissive '+all' mechanism allows any server to send email")
        
        # Check for syntax errors
        if not spf_record.startswith('v=spf1 '):
            issues.append("SPF record must start with 'v=spf1 '")
        
        return issues
    
    def _validate_dmarc_record(self, dmarc_record: str) -> List[str]:
        """Validate DMARC record for common issues."""
        issues = []
        
        # Check for required tags
        if 'p=' not in dmarc_record:
            issues.append("Missing required 'p=' (policy) tag")
        
        # Check policy strength
        if 'p=none' in dmarc_record:
            issues.append("DMARC policy set to 'none' - provides monitoring only, no enforcement")
        
        # Check for reporting addresses
        if 'rua=' not in dmarc_record and 'ruf=' not in dmarc_record:
            issues.append("No reporting addresses configured - missing visibility into email authentication failures")
        
        # Check percentage
        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct < 100:
                issues.append(f"DMARC policy applies to only {pct}% of emails")
        
        return issues
    
    def _analyze_email_security(self, results: Dict[str, Any]) -> None:
        """Analyze email security configuration for vulnerabilities."""
        
        # SPF vulnerabilities
        if not results['spf']['exists']:
            results['vulnerabilities'].append({
                'type': 'missing_spf_record',
                'severity': 'high',
                'description': 'No SPF record found - email spoofing possible',
                'remediation': 'Configure SPF record to specify authorized email servers',
                'mitre_technique': 'T1566.001'  # Phishing: Spearphishing Attachment
            })
        elif results['spf']['issues']:
            for issue in results['spf']['issues']:
                severity = 'high' if 'allows any server' in issue else 'medium'
                results['vulnerabilities'].append({
                    'type': 'spf_misconfiguration',
                    'severity': severity,
                    'description': f"SPF record issue: {issue}",
                    'remediation': 'Fix SPF record configuration',
                    'mitre_technique': 'T1566.001'
                })
        
        # DMARC vulnerabilities
        if not results['dmarc']['exists']:
            results['vulnerabilities'].append({
                'type': 'missing_dmarc_record',
                'severity': 'high',
                'description': 'No DMARC record found - email authentication enforcement disabled',
                'remediation': 'Configure DMARC record with appropriate policy',
                'mitre_technique': 'T1566.001'
            })
        elif results['dmarc']['issues']:
            for issue in results['dmarc']['issues']:
                severity = 'medium' if 'p=none' in issue else 'low'
                results['vulnerabilities'].append({
                    'type': 'dmarc_misconfiguration',
                    'severity': severity,
                    'description': f"DMARC record issue: {issue}",
                    'remediation': 'Improve DMARC record configuration',
                    'mitre_technique': 'T1566.001'
                })
        
        # DKIM vulnerabilities
        if not results['dkim']['selectors_found']:
            results['vulnerabilities'].append({
                'type': 'missing_dkim_records',
                'severity': 'medium',
                'description': 'No DKIM records found - email integrity cannot be verified',
                'remediation': 'Configure DKIM signing and publish DKIM public keys',
                'mitre_technique': 'T1566.001'
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