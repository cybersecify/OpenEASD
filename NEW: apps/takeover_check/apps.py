Looking at the existing codebase, I can see this is a Django project written in Python, not TypeScript. The bounty description mentions TypeScript but the existing code is clearly Python. I'll implement the subdomain takeover detection following the existing Django patterns.

```python
// NEW: apps/takeover_check/apps.py
from django.apps import AppConfig


class TakeoverCheckConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.takeover_check"
    label = "takeover_check"
    verbose_name = "Subdomain Takeover Check"
    tool_meta = {
        "label": "Takeover Check",
        "runner": "apps.takeover_check.scanner.run_takeover_check",
        "phase": 3,
        "requires": ["subdomain"],
        "produces_findings": True,
    }
```

```python
// NEW: apps/takeover_check/scanner.py
"""Subdomain takeover detection scanner."""

import logging
from apps.core.assets.models import Subdomain, Finding
from .collector import collect_dns_data
from .analyzer import analyze_takeover_vulnerability

logger = logging.getLogger(__name__)


def run_takeover_check(session) -> list:
    """Run subdomain takeover detection against session subdomains."""
    # Get all subdomains for this session
    subdomains = Subdomain.objects.filter(session=session)
    if not subdomains:
        logger.info(f"[takeover:{session.id}] No subdomains to check")
        return []
    
    findings = []
    for subdomain in subdomains:
        dns_data = collect_dns_data(subdomain.name)
        if dns_data:
            vulnerability = analyze_takeover_vulnerability(subdomain.name, dns_data)
            if vulnerability:
                finding = Finding(
                    session=session,
                    subdomain=subdomain,
                    source="takeover_check",
                    severity=vulnerability["severity"],
                    title=f"Subdomain Takeover: {subdomain.name}",
                    description=vulnerability["description"],
                    evidence=vulnerability["evidence"],
                    platform=vulnerability["platform"]
                )
                findings.append(finding)
    
    if findings:
        Finding.objects.bulk_create(findings, ignore_conflicts=True)
        logger.info(f"[takeover:{session.id}] Found {len(findings)} takeover vulnerabilities")
    
    return findings
```

```python
// NEW: apps/takeover_check/collector.py
"""DNS data collection for subdomain takeover detection."""

import logging
import dns.resolver
import dns.exception
import requests
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def collect_dns_data(subdomain: str) -> Optional[Dict]:
    """Collect DNS records and HTTP response for takeover detection."""
    try:
        data = {
            "subdomain": subdomain,
            "cname_chain": [],
            "a_records": [],
            "http_response": None,
            "http_status": None
        }
        
        # Resolve CNAME chain
        try:
            cname_response = dns.resolver.resolve(subdomain, 'CNAME')
            for cname in cname_response:
                data["cname_chain"].append(str(cname).rstrip('.'))
        except dns.exception.DNSException:
            pass
        
        # Get A records
        try:
            a_response = dns.resolver.resolve(subdomain, 'A')
            for a in a_response:
                data["a_records"].append(str(a))
        except dns.exception.DNSException:
            pass
        
        # Get HTTP response
        try:
            response = requests.get(f"http://{subdomain}", timeout=10, allow_redirects=False)
            data["http_status"] = response.status_code
            data["http_response"] = response.text[:2048]  # Limit response size
        except requests.RequestException:
            try:
                response = requests.get(f"https://{subdomain}", timeout=10, allow_redirects=False)
                data["http_status"] = response.status_code  
                data["http_response"] = response.text[:2048]
            except requests.RequestException:
                pass
        
        return data
        
    except Exception as e:
        logger.warning(f"Error collecting DNS data for {subdomain}: {e}")
        return None
```

```python
// NEW: apps/takeover_check/analyzer.py
"""Subdomain takeover vulnerability analysis with platform fingerprinting."""

import logging
import re
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Platform fingerprints for subdomain takeover detection
TAKEOVER_FINGERPRINTS = {
    "aws_s3": {
        "cname_patterns": [r".*\.s3.*\.amazonaws\.com", r".*\.s3-website.*\.amazonaws\.com"],
        "error_patterns": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
        "description": "AWS S3 bucket not found - subdomain can be claimed by registering bucket"
    },
    "github_pages": {
        "cname_patterns": [r".*\.github\.io", r".*\.githubusercontent\.com"],
        "error_patterns": ["There isn't a GitHub Pages site here", "404 - File not found"],
        "severity": "high", 
        "description": "GitHub Pages site not found - subdomain can be claimed by creating repository"
    },
    "heroku": {
        "cname_patterns": [r".*\.herokuapp\.com", r".*\.herokudns\.com"],
        "error_patterns": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "severity": "high",
        "description": "Heroku app not found - subdomain can be claimed by creating app"
    },
    "fastly": {
        "cname_patterns": [r".*\.fastly\.com", r".*\.fastlylb\.net"],
        "error_patterns": ["Fastly error: unknown domain", "Please check that this domain has been added"],
        "severity": "medium",
        "description": "Fastly service not configured - potential subdomain takeover"
    },
    "azure": {
        "cname_patterns": [r".*\.azurewebsites\.net", r".*\.cloudapp\.azure\.com", r".*\.trafficmanager\.net"],
        "error_patterns": ["Web app doesn't exist", "Error 404 - Web app not found"],
        "severity": "high",
        "description": "Azure resource not found - subdomain can be claimed by creating resource"
    },
    "cloudfront": {
        "cname_patterns": [r".*\.cloudfront\.net"],
        "error_patterns": ["Bad Request", "The request could not be satisfied"],
        "severity": "medium",
        "description": "CloudFront distribution misconfigured - potential subdomain takeover"
    },
    "shopify": {
        "cname_patterns": [r".*\.myshopify\.com"],
        "error_patterns": ["Sorry, this shop is currently unavailable", "Only one step left!"],
        "severity": "high",
        "description": "Shopify store not found - subdomain can be claimed by creating store"
    },
    "unbounce": {
        "cname_patterns": [r".*\.unbouncepages\.com"],
        "error_patterns": ["The requested URL was not found on this server", "Uh oh. Something's not right"],
        "severity": "high", 
        "description": "Unbounce page not found - subdomain can be claimed"
    },
    "cargo": {
        "cname_patterns": [r".*\.cargocollective\.com"],
        "error_patterns": ["404 Not Found", "If you're looking for someone's site"],
        "severity": "medium",
        "description": "Cargo Collective site not found - potential subdomain takeover"
    },
    "surge": {
        "cname_patterns": [r".*\.surge\.sh"],
        "error_patterns": ["project not found"],
        "severity": "high",
        "description": "Surge.sh project not found - subdomain can be claimed"
    }
}


def analyze_takeover_vulnerability(subdomain: str, dns_data: Dict) -> Optional[Dict]:
    """Analyze DNS data for subdomain takeover vulnerabilities."""
    
    # Check if we have CNAME records pointing to vulnerable platforms
    for cname in dns_data.get("cname_chain", []):
        for platform, fingerprint in TAKEOVER_FINGERPRINTS.items():
            # Check if CNAME matches platform patterns
            for pattern in fingerprint["cname_patterns"]:
                if re.match(pattern, cname, re.IGNORECASE):
                    # Check if HTTP response contains error patterns
                    http_response = dns_data.get("http_response", "")
                    if http_response:
                        for error_pattern in fingerprint["error_patterns"]:
                            if error_pattern.lower() in http_response.lower():
                                return {
                                    "platform": platform,
                                    "severity": fingerprint["severity"],
                                    "description": fingerprint["description"],
                                    "evidence": {
                                        "cname": cname,
                                        "http_status": dns_data.get("http_status"),
                                        "error_snippet": _extract_error_context(http_response, error_pattern)
                                    }
                                }
    
    return None


def _extract_error_context(response: str, error_pattern: str, context_chars: int = 200) -> str:
    """Extract context around error pattern for evidence."""
    try:
        index = response.lower().find(error_pattern.lower())
        if index == -1:
            return error_pattern
        
        start = max(0, index - context_chars // 2)
        end = min(len(response), index + len(error_pattern) + context_chars // 2)
        
        return response[start:end].strip()
    except Exception:
        return error_pattern
```

```python
// MODIFY: apps/core/assets/models.py
from django.db import models


class Subdomain(models.Model):
    session = models.ForeignKey('core.Session', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    source = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['session', 'name']


class Finding(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'), 
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    session = models.ForeignKey('core.Session', on_delete=models.CASCADE)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    source = models.CharField(max_length=50)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=255)
    description = models.TextField()
    evidence = models.JSONField(default=dict)
    platform = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['session', 'subdomain', 'source', 'title']
```

```python
// NEW: apps/takeover_check/__init__.py
```