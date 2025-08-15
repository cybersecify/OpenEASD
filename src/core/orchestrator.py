"""Prefect workflow orchestration for OpenEASD."""

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import asyncio
import json
import logging

from .database import DatabaseManager
from .config_manager import ConfigManager
from .delta_detector import DeltaDetector

# Import module classes
from ..modules.apex_domain_security.dns_analyzer import DNSAnalyzer
from ..modules.apex_domain_security.ssl_checker import SSLChecker
from ..modules.apex_domain_security.email_security import EmailSecurity
from ..modules.apex_domain_security.cybersquatting import CybersquattingDetector

logger = logging.getLogger(__name__)


class SecurityScanOrchestrator:
    """Main orchestrator for security scans with API integration."""
    
    def __init__(self, config_manager: 'ConfigManager', db_manager: 'DatabaseManager'):
        self.config = config_manager
        self.db = db_manager
        self.scan_orchestrator = ScanOrchestrator()
        
    async def start_scan(self, domain: str, scan_type: str = "full"):
        """Start a security scan for a domain"""
        try:
            logger.info(f"Starting {scan_type} scan for domain: {domain}")
            
            # Create scan session in database
            session_data = {
                'domain': domain,
                'scan_type': scan_type,
                'start_time': datetime.now(),
                'status': 'running'
            }
            
            # For now, return a mock session object
            # In a full implementation, this would start the actual Prefect flow
            session = type('ScanSession', (), {
                'id': 1,
                'domain': domain,
                'scan_type': scan_type,
                'status': 'running'
            })()
            
            logger.info(f"Scan session {session.id} created for {domain}")
            return session
            
        except Exception as e:
            logger.error(f"Error starting scan: {e}")
            raise
    
    async def get_scan_status(self, session_id: int):
        """Get the status of a scan session"""
        try:
            # Mock status for now
            return {
                'session_id': session_id,
                'status': 'running',
                'progress': '25%',
                'current_phase': 'DNS Analysis',
                'started_at': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting scan status: {e}")
            raise
    
    async def get_scan_results(self, session_id: int):
        """Get the results of a completed scan"""
        try:
            # Mock results for now
            return {
                'session_id': session_id,
                'status': 'completed',
                'findings': [
                    {
                        'type': 'DNS Analysis',
                        'severity': 'info',
                        'description': 'Domain resolution successful',
                        'details': 'DNS records found and validated'
                    }
                ],
                'summary': {
                    'total_findings': 1,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 1
                }
            }
        except Exception as e:
            logger.error(f"Error getting scan results: {e}")
            raise


class ScanOrchestrator:
    """Orchestrates security scanning workflows using Prefect."""
    
    def __init__(self, config_path: str = "config/default_config.yaml"):
        self.config = ConfigManager(config_path)
        self.db = DatabaseManager(self.config.get('database.path', 'data/openeasd.db'))
        self.delta_detector = DeltaDetector(self.db)
    
    @flow(name="openeasd-security-scan", task_runner=ConcurrentTaskRunner())
    def security_scan_flow(self, domain: str, scan_type: str = "full") -> Dict[str, Any]:
        """
        Main security scanning workflow.
        
        Args:
            domain: Target domain to scan
            scan_type: 'full' or 'incremental'
            
        Returns:
            Dictionary containing all scan results
        """
        logger = get_run_logger()
        logger.info(f"Starting {scan_type} security scan for {domain}")
        
        # Create scan session
        config_hash = self.config.get_config_hash()
        session_id = self.db.create_scan_session(domain, scan_type, config_hash)
        
        try:
            # Phase 1: Apex Domain Security
            apex_results = apex_domain_security_task.submit(domain, self.config.get_dict())
            
            # Phase 2: Service Detection (depends on apex results for subdomains)
            service_results = service_detection_task.submit(
                domain, apex_results, self.config.get_dict(), wait_for=[apex_results]
            )
            
            # Phase 3: Web Security Assessment
            web_results = web_security_task.submit(
                service_results, self.config.get_dict(), wait_for=[service_results]
            )
            
            # Phase 4: Collect and store results
            final_results = collect_results_task.submit(
                session_id, apex_results, service_results, web_results,
                wait_for=[apex_results, service_results, web_results]
            )
            
            # Phase 5: Delta detection for incremental scans
            delta_results = None
            if scan_type == "incremental":
                delta_results = delta_detection_task.submit(
                    session_id, domain, wait_for=[final_results]
                )
            
            # Phase 6: Alert processing
            alert_results = alert_processing_task.submit(
                session_id, self.config.get_dict(), delta_results,
                wait_for=[final_results, delta_results] if delta_results else [final_results]
            )
            
            # Update scan session as completed
            self.db.update_scan_session(
                session_id, 
                status="completed", 
                end_time=datetime.utcnow()
            )
            
            logger.info(f"Security scan completed for {domain}")
            
            return {
                "session_id": session_id,
                "domain": domain,
                "scan_type": scan_type,
                "apex_results": apex_results.result(),
                "service_results": service_results.result(),
                "web_results": web_results.result(),
                "delta_results": delta_results.result() if delta_results else None,
                "alert_results": alert_results.result()
            }
            
        except Exception as e:
            logger.error(f"Scan failed for {domain}: {str(e)}")
            self.db.update_scan_session(
                session_id,
                status="failed",
                end_time=datetime.utcnow()
            )
            raise


@task(name="apex-domain-security")
def apex_domain_security_task(domain: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute apex domain security checks."""
    logger = get_run_logger()
    logger.info(f"Starting apex domain security checks for {domain}")
    
    results = {
        'domain': domain,
        'timestamp': datetime.utcnow().isoformat(),
        'dns_analysis': {},
        'ssl_analysis': {},
        'email_security': {},
        'cybersquatting': {},
        'vulnerabilities': [],
        'subdomains': []
    }
    
    try:
        # DNS Analysis
        dns_analyzer = DNSAnalyzer()
        dns_results = dns_analyzer.dns_record_analysis(domain)
        results['dns_analysis'] = dns_results
        results['vulnerabilities'].extend(dns_results.get('vulnerabilities', []))
        
        # SSL/TLS Analysis
        ssl_checker = SSLChecker()
        ssl_results = ssl_checker.ssl_certificate_validation(domain)
        results['ssl_analysis'] = ssl_results
        results['vulnerabilities'].extend(ssl_results.get('vulnerabilities', []))
        
        # Email Security Analysis
        email_security = EmailSecurity()
        email_results = email_security.spf_dmarc_checker(domain)
        results['email_security'] = email_results
        results['vulnerabilities'].extend(email_results.get('vulnerabilities', []))
        
        # Cybersquatting Detection
        cybersquatting = CybersquattingDetector()
        cybersquatting_results = cybersquatting.tld_cybersquatting_detection(domain)
        results['cybersquatting'] = cybersquatting_results
        results['vulnerabilities'].extend(cybersquatting_results.get('vulnerabilities', []))
        
        logger.info(f"Apex domain security completed for {domain}")
        
    except Exception as e:
        logger.error(f"Error in apex domain security for {domain}: {str(e)}")
        results['error'] = str(e)
    
    return results


@task(name="service-detection")
def service_detection_task(domain: str, apex_results: Dict[str, Any], 
                          config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute service detection and port scanning."""
    logger = get_run_logger()
    logger.info(f"Starting service detection for {domain}")
    
    # This would integrate with actual tools like Subfinder, Naabu, Nmap
    # For now, providing structure for integration
    
    results = {
        'domain': domain,
        'timestamp': datetime.utcnow().isoformat(),
        'subdomains': [],
        'services': [],
        'vulnerabilities': []
    }
    
    try:
        # Extract any subdomains found in apex analysis
        if apex_results and 'subdomains' in apex_results:
            results['subdomains'].extend(apex_results['subdomains'])
        
        # TODO: Integrate with actual tools
        # - Subfinder for subdomain enumeration
        # - Naabu for port scanning
        # - Nmap for service fingerprinting
        
        # Placeholder for tool integration
        logger.info("Service detection tools would be executed here")
        logger.info(f"Would scan subdomains: {results['subdomains']}")
        
        logger.info(f"Service detection completed for {domain}")
        
    except Exception as e:
        logger.error(f"Error in service detection for {domain}: {str(e)}")
        results['error'] = str(e)
    
    return results


@task(name="web-security")
def web_security_task(service_results: Dict[str, Any], 
                     config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute web security assessments."""
    logger = get_run_logger()
    logger.info("Starting web security assessment")
    
    results = {
        'timestamp': datetime.utcnow().isoformat(),
        'security_headers': [],
        'admin_panels': [],
        'vulnerabilities': []
    }
    
    try:
        # TODO: Integrate with actual tools
        # - Nuclei for vulnerability scanning
        # - Custom scripts for header checking
        # - Admin panel detection
        
        # Extract services from service detection results
        services = service_results.get('services', [])
        logger.info(f"Would perform web security checks on {len(services)} services")
        
        logger.info("Web security assessment completed")
        
    except Exception as e:
        logger.error(f"Error in web security assessment: {str(e)}")
        results['error'] = str(e)
    
    return results


@task(name="collect-results")
def collect_results_task(session_id: int, apex_results: Dict[str, Any],
                        service_results: Dict[str, Any], web_results: Dict[str, Any]) -> Dict[str, Any]:
    """Collect and store all scan results in database."""
    logger = get_run_logger()
    logger.info(f"Collecting results for session {session_id}")
    
    db = DatabaseManager()
    
    try:
        # Store subdomains
        subdomains = []
        if apex_results.get('subdomains'):
            subdomains.extend(apex_results['subdomains'])
        if service_results.get('subdomains'):
            subdomains.extend(service_results['subdomains'])
        
        if subdomains:
            db.insert_subdomains(session_id, subdomains)
        
        # Store services
        services = service_results.get('services', [])
        if services:
            db.insert_services(session_id, services)
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        for results in [apex_results, service_results, web_results]:
            if results and results.get('vulnerabilities'):
                all_vulnerabilities.extend(results['vulnerabilities'])
        
        if all_vulnerabilities:
            db.insert_vulnerabilities(session_id, all_vulnerabilities)
        
        # Update total findings count
        db.update_scan_session(session_id, total_findings=len(all_vulnerabilities))
        
        logger.info(f"Results stored: {len(subdomains)} subdomains, "
                   f"{len(services)} services, {len(all_vulnerabilities)} vulnerabilities")
        
        return {
            'session_id': session_id,
            'subdomains_count': len(subdomains),
            'services_count': len(services),
            'vulnerabilities_count': len(all_vulnerabilities)
        }
        
    except Exception as e:
        logger.error(f"Error collecting results for session {session_id}: {str(e)}")
        raise


@task(name="delta-detection")
def delta_detection_task(session_id: int, domain: str) -> Dict[str, Any]:
    """Detect changes from previous scan."""
    logger = get_run_logger()
    logger.info(f"Running delta detection for session {session_id}")
    
    db = DatabaseManager()
    delta_detector = DeltaDetector(db)
    
    try:
        # Get previous scan session
        previous_session = db.get_latest_session(domain, 'full')
        if not previous_session or previous_session['id'] == session_id:
            logger.info("No previous scan found for delta detection")
            return {'changes': [], 'previous_session_id': None}
        
        # Detect changes
        changes = delta_detector.detect_changes(session_id, previous_session['id'])
        
        logger.info(f"Delta detection completed: {len(changes)} changes found")
        
        return {
            'changes': changes,
            'previous_session_id': previous_session['id'],
            'change_summary': delta_detector.summarize_changes(changes)
        }
        
    except Exception as e:
        logger.error(f"Error in delta detection for session {session_id}: {str(e)}")
        return {'error': str(e)}


@task(name="alert-processing")
def alert_processing_task(session_id: int, config: Dict[str, Any], 
                         delta_results: Dict[str, Any] = None) -> Dict[str, Any]:
    """Process and send alerts for scan findings."""
    logger = get_run_logger()
    logger.info(f"Processing alerts for session {session_id}")
    
    db = DatabaseManager()
    
    try:
        # Get vulnerabilities that meet alert threshold
        alert_config = config.get('alerts', {})
        severity_threshold = alert_config.get('severity_threshold', 'medium')
        
        # Define severity order for filtering
        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold_level = severity_order.get(severity_threshold, 2)
        
        vulnerabilities = db.get_vulnerabilities(session_id)
        alert_worthy = [v for v in vulnerabilities 
                       if severity_order.get(v['severity'], 1) >= threshold_level]
        
        # Focus on new findings if this is an incremental scan
        if delta_results and delta_results.get('changes'):
            new_vulnerabilities = [v for v in alert_worthy if v.get('is_new', True)]
            if new_vulnerabilities:
                alert_worthy = new_vulnerabilities
        
        alerts_sent = []
        
        # TODO: Implement actual alert sending
        # This would integrate with Slack, email, or other notification systems
        
        for vuln in alert_worthy:
            # Create alert record
            alert_id = db.insert_alert(
                vuln['id'], session_id, 'slack', 
                severity_threshold, f"Vulnerability found: {vuln['title']}"
            )
            
            # TODO: Send actual alert
            logger.info(f"Would send alert for vulnerability: {vuln['title']}")
            
            # Update alert status
            db.update_alert_status(alert_id, 'sent')
            alerts_sent.append(alert_id)
        
        logger.info(f"Alert processing completed: {len(alerts_sent)} alerts sent")
        
        return {
            'alerts_sent': len(alerts_sent),
            'alert_ids': alerts_sent,
            'vulnerabilities_processed': len(alert_worthy)
        }
        
    except Exception as e:
        logger.error(f"Error processing alerts for session {session_id}: {str(e)}")
        return {'error': str(e)}


# Scheduled flows for automation
@flow(name="daily-incremental-scan")
def daily_incremental_scan(domain: str) -> Dict[str, Any]:
    """Daily incremental security scan."""
    orchestrator = ScanOrchestrator()
    return orchestrator.security_scan_flow(domain, scan_type="incremental")


@flow(name="weekly-full-scan")
def weekly_full_scan(domain: str) -> Dict[str, Any]:
    """Weekly comprehensive security scan."""
    orchestrator = ScanOrchestrator()
    return orchestrator.security_scan_flow(domain, scan_type="full")