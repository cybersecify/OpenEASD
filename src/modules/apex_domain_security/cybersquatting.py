"""Cybersquatting detection module for TLD variant analysis."""

import dns.resolver
import dns.exception
from typing import Dict, List, Any, Set
from datetime import datetime
import itertools
import logging

logger = logging.getLogger(__name__)


class CybersquattingDetector:
    """Detects potential cybersquatting domains and TLD variants."""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 15
        
        # Common TLDs for cybersquatting
        self.common_tlds = [
            'com', 'org', 'net', 'info', 'biz', 'co', 'io', 'me', 'tv',
            'cc', 'us', 'uk', 'ca', 'de', 'fr', 'jp', 'cn', 'ru', 'in'
        ]
        
        # Character substitutions for typosquatting
        self.char_substitutions = {
            'a': ['@', 'e', 'o'],
            'e': ['3', 'a'],
            'i': ['1', 'l', 'j'],
            'o': ['0', 'a'],
            'u': ['v'],
            's': ['5', '$'],
            'g': ['9', 'q'],
            'l': ['1', 'i'],
            'm': ['n', 'rn'],
            'n': ['m'],
            'r': ['t'],
            't': ['f'],
            'w': ['vv'],
            'x': ['*']
        }
    
    def tld_cybersquatting_detection(self, domain: str) -> Dict[str, Any]:
        """
        Detect domain variants across TLDs and typosquatting attempts.
        
        Args:
            domain: Target domain to analyze (without TLD)
            
        Returns:
            Dictionary containing cybersquatting analysis results
        """
        # Extract domain name without TLD
        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            domain_name = domain_parts[0]
            original_tld = '.'.join(domain_parts[1:])
        else:
            domain_name = domain
            original_tld = 'com'  # Default assumption
        
        results = {
            'target_domain': domain,
            'domain_name': domain_name,
            'original_tld': original_tld,
            'timestamp': datetime.utcnow().isoformat(),
            'tld_variants': {},
            'typo_variants': {},
            'suspicious_domains': [],
            'vulnerabilities': [],
            'risk_level': 'low'
        }
        
        # Check TLD variants
        results['tld_variants'] = self._check_tld_variants(domain_name, original_tld)
        
        # Check typosquatting variants (limited to avoid excessive DNS queries)
        results['typo_variants'] = self._check_typo_variants(domain_name, original_tld)
        
        # Analyze for suspicious activity
        self._analyze_cybersquatting_risk(results)
        
        # Determine overall risk level
        results['risk_level'] = self._calculate_risk_level(results['vulnerabilities'])
        
        return results
    
    def _check_tld_variants(self, domain_name: str, original_tld: str) -> Dict[str, Any]:
        """Check for registered domains with different TLDs."""
        tld_results = {
            'checked_tlds': [],
            'registered_variants': [],
            'suspicious_variants': []
        }
        
        for tld in self.common_tlds:
            if tld == original_tld:
                continue
                
            variant_domain = f"{domain_name}.{tld}"
            tld_results['checked_tlds'].append(tld)
            
            try:
                # Check if domain resolves
                answers = self.resolver.resolve(variant_domain, 'A')
                if answers:
                    variant_info = {
                        'domain': variant_domain,
                        'tld': tld,
                        'ip_addresses': [str(rdata) for rdata in answers],
                        'suspicious_indicators': []
                    }
                    
                    # Check for suspicious indicators
                    self._check_domain_suspicion(variant_info)
                    
                    tld_results['registered_variants'].append(variant_info)
                    
                    if variant_info['suspicious_indicators']:
                        tld_results['suspicious_variants'].append(variant_info)
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException as e:
                logger.debug(f"DNS error checking {variant_domain}: {e}")
                continue
        
        return tld_results
    
    def _check_typo_variants(self, domain_name: str, original_tld: str, max_variants: int = 20) -> Dict[str, Any]:
        """Check for registered typosquatting variants."""
        typo_results = {
            'generated_variants': [],
            'registered_variants': [],
            'suspicious_variants': []
        }
        
        # Generate typo variants
        typo_variants = self._generate_typo_variants(domain_name, max_variants)
        typo_results['generated_variants'] = typo_variants
        
        for variant in typo_variants:
            variant_domain = f"{variant}.{original_tld}"
            
            try:
                # Check if variant domain resolves
                answers = self.resolver.resolve(variant_domain, 'A')
                if answers:
                    variant_info = {
                        'domain': variant_domain,
                        'variant_type': 'typosquatting',
                        'ip_addresses': [str(rdata) for rdata in answers],
                        'suspicious_indicators': []
                    }
                    
                    # Check for suspicious indicators
                    self._check_domain_suspicion(variant_info)
                    
                    typo_results['registered_variants'].append(variant_info)
                    
                    if variant_info['suspicious_indicators']:
                        typo_results['suspicious_variants'].append(variant_info)
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException as e:
                logger.debug(f"DNS error checking {variant_domain}: {e}")
                continue
        
        return typo_results
    
    def _generate_typo_variants(self, domain_name: str, max_variants: int) -> List[str]:
        """Generate typosquatting variants of domain name."""
        variants = set()
        
        # Character substitution variants
        for i, char in enumerate(domain_name.lower()):
            if char in self.char_substitutions:
                for substitute in self.char_substitutions[char]:
                    variant = domain_name[:i] + substitute + domain_name[i+1:]
                    variants.add(variant)
                    if len(variants) >= max_variants // 3:
                        break
        
        # Character omission variants
        for i in range(len(domain_name)):
            if len(domain_name) > 3:  # Don't make domain too short
                variant = domain_name[:i] + domain_name[i+1:]
                variants.add(variant)
                if len(variants) >= max_variants * 2 // 3:
                    break
        
        # Character insertion variants (adjacent key typos)
        adjacent_keys = {
            'a': 's', 'b': 'vn', 'c': 'xv', 'd': 'sf', 'e': 'wr',
            'f': 'dg', 'g': 'fh', 'h': 'gj', 'i': 'uo', 'j': 'hk',
            'k': 'jl', 'l': 'k', 'm': 'n', 'n': 'bm', 'o': 'ip',
            'p': 'o', 'q': 'w', 'r': 'et', 's': 'ad', 't': 'ry',
            'u': 'yi', 'v': 'cb', 'w': 'qe', 'x': 'zc', 'y': 'tu',
            'z': 'x'
        }
        
        for i, char in enumerate(domain_name.lower()):
            if char in adjacent_keys:
                for adjacent in adjacent_keys[char]:
                    variant = domain_name[:i] + adjacent + domain_name[i:]
                    variants.add(variant)
                    if len(variants) >= max_variants:
                        break
        
        # Remove original domain and return limited set
        variants.discard(domain_name)
        return list(variants)[:max_variants]
    
    def _check_domain_suspicion(self, variant_info: Dict[str, Any]) -> None:
        """Check domain for suspicious indicators."""
        domain = variant_info['domain']
        ip_addresses = variant_info['ip_addresses']
        
        # Check for suspicious hosting patterns
        suspicious_indicators = []
        
        # Check for bulletproof hosting / suspicious IP ranges
        for ip in ip_addresses:
            if self._is_suspicious_ip(ip):
                suspicious_indicators.append(f"Suspicious IP range: {ip}")
        
        # Check for domain parking indicators
        try:
            # Simple check for common domain parking services
            parking_indicators = ['sedoparking', 'parkingcrew', 'bodis', 'smartname']
            # This would require HTTP request to check content - simplified for DNS-only check
            
            # Check for wildcard DNS (simplified)
            if len(set(ip_addresses)) == 1 and len(ip_addresses) > 1:
                suspicious_indicators.append("Possible wildcard DNS configuration")
                
        except Exception as e:
            logger.debug(f"Error checking domain parking for {domain}: {e}")
        
        variant_info['suspicious_indicators'] = suspicious_indicators
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is in suspicious ranges."""
        # This is a simplified check - in production, you'd use threat intelligence feeds
        suspicious_ranges = [
            '185.53.179.',  # Known malicious hosting
            '192.42.116.',  # Bulletproof hosting example
            # Add more suspicious IP ranges as needed
        ]
        
        return any(ip.startswith(range_prefix) for range_prefix in suspicious_ranges)
    
    def _analyze_cybersquatting_risk(self, results: Dict[str, Any]) -> None:
        """Analyze results for cybersquatting vulnerabilities."""
        
        # Check TLD variants
        tld_variants = results['tld_variants']
        registered_count = len(tld_variants['registered_variants'])
        suspicious_count = len(tld_variants['suspicious_variants'])
        
        if registered_count > 5:
            results['vulnerabilities'].append({
                'type': 'extensive_tld_squatting',
                'severity': 'medium',
                'description': f"Found {registered_count} registered TLD variants of domain",
                'remediation': 'Consider defensive registration of important TLD variants',
                'mitre_technique': 'T1583.001'  # Acquire Infrastructure: Domains
            })
        
        if suspicious_count > 0:
            results['vulnerabilities'].append({
                'type': 'suspicious_domain_variants',
                'severity': 'high',
                'description': f"Found {suspicious_count} suspicious domain variants",
                'remediation': 'Investigate suspicious domains and consider takedown requests',
                'mitre_technique': 'T1583.001'
            })
            
            # Add suspicious domains to results
            results['suspicious_domains'].extend(
                variant['domain'] for variant in tld_variants['suspicious_variants']
            )
        
        # Check typo variants
        typo_variants = results['typo_variants']
        typo_registered = len(typo_variants['registered_variants'])
        typo_suspicious = len(typo_variants['suspicious_variants'])
        
        if typo_registered > 3:
            results['vulnerabilities'].append({
                'type': 'typosquatting_domains',
                'severity': 'medium',
                'description': f"Found {typo_registered} registered typosquatting variants",
                'remediation': 'Monitor typosquatting domains for malicious activity',
                'mitre_technique': 'T1583.001'
            })
        
        if typo_suspicious > 0:
            results['vulnerabilities'].append({
                'type': 'suspicious_typosquatting',
                'severity': 'high',
                'description': f"Found {typo_suspicious} suspicious typosquatting domains",
                'remediation': 'Investigate and report malicious typosquatting domains',
                'mitre_technique': 'T1583.001'
            })
            
            # Add suspicious typo domains to results
            results['suspicious_domains'].extend(
                variant['domain'] for variant in typo_variants['suspicious_variants']
            )
    
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