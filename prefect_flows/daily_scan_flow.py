"""Daily incremental scan flow for OpenEASD."""

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner
from typing import Dict, List, Any
from datetime import datetime, timedelta
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.orchestrator import ScanOrchestrator
from core.config_manager import ConfigManager
from core.database import DatabaseManager


@flow(
    name="openeasd-daily-incremental-scan",
    task_runner=ConcurrentTaskRunner(),
    description="Daily incremental security scan for OpenEASD"
)
def daily_incremental_scan_flow(domain: str, config_path: str = "config/default_config.yaml") -> Dict[str, Any]:
    """
    Execute daily incremental security scan.
    
    Args:
        domain: Target domain to scan
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing scan results and summary
    """
    logger = get_run_logger()
    logger.info(f"Starting daily incremental scan for domain: {domain}")
    
    try:
        # Initialize orchestrator
        orchestrator = ScanOrchestrator(config_path)
        
        # Execute incremental scan
        scan_results = orchestrator.security_scan_flow(domain, scan_type="incremental")
        
        # Generate summary for daily report
        summary = generate_daily_summary.submit(scan_results)
        
        # Send notifications if configured
        notification_result = send_daily_notifications.submit(scan_results, summary)
        
        logger.info(f"Daily incremental scan completed for {domain}")
        
        return {
            'scan_type': 'incremental',
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'scan_results': scan_results,
            'summary': summary.result(),
            'notifications_sent': notification_result.result()
        }
        
    except Exception as e:
        logger.error(f"Daily incremental scan failed for {domain}: {str(e)}")
        raise


@task(name="generate-daily-summary")
def generate_daily_summary(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate daily scan summary."""
    logger = get_run_logger()
    
    try:
        session_id = scan_results.get('session_id')
        if not session_id:
            return {'error': 'No session ID found in scan results'}
        
        # Get results from database
        db = DatabaseManager()
        vulnerabilities = db.get_vulnerabilities(session_id)
        services = db.get_services(session_id)
        subdomains = db.get_subdomains(session_id)
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        new_vulnerabilities = []
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Track new vulnerabilities for incremental scans
            if vuln.get('is_new', False):
                new_vulnerabilities.append({
                    'title': vuln.get('title', vuln.get('vulnerability_type', 'Unknown')),
                    'severity': severity,
                    'host': vuln.get('host', ''),
                    'description': vuln.get('description', '')
                })
        
        summary = {
            'session_id': session_id,
            'scan_date': datetime.utcnow().date().isoformat(),
            'total_subdomains': len(subdomains),
            'total_services': len(services),
            'total_vulnerabilities': len(vulnerabilities),
            'new_vulnerabilities': len(new_vulnerabilities),
            'severity_breakdown': severity_counts,
            'new_findings': new_vulnerabilities[:10],  # Top 10 new findings
            'requires_attention': severity_counts.get('critical', 0) > 0 or severity_counts.get('high', 0) > 3
        }
        
        logger.info(f"Generated daily summary: {len(vulnerabilities)} total vulnerabilities, "
                   f"{len(new_vulnerabilities)} new findings")
        
        return summary
        
    except Exception as e:
        logger.error(f"Error generating daily summary: {str(e)}")
        return {'error': str(e)}


@task(name="send-daily-notifications")  
def send_daily_notifications(scan_results: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, Any]:
    """Send daily scan notifications if configured."""
    logger = get_run_logger()
    
    try:
        config = ConfigManager()
        
        # Check if notifications are enabled
        slack_enabled = config.is_alert_enabled('slack')
        email_enabled = config.is_alert_enabled('email')
        
        notifications_sent = []
        
        if not slack_enabled and not email_enabled:
            logger.info("No notification channels enabled")
            return {'notifications_sent': 0}
        
        # Only send notifications if there are new findings or critical issues
        should_notify = (
            summary.get('new_vulnerabilities', 0) > 0 or
            summary.get('requires_attention', False)
        )
        
        if not should_notify:
            logger.info("No new findings requiring notification")
            return {'notifications_sent': 0}
        
        # Prepare notification message
        domain = scan_results.get('domain', 'Unknown')
        new_vulns = summary.get('new_vulnerabilities', 0)
        critical_count = summary.get('severity_breakdown', {}).get('critical', 0)
        high_count = summary.get('severity_breakdown', {}).get('high', 0)
        
        message = f"🔍 Daily Security Scan Results for {domain}\n\n"
        message += f"📊 Summary:\n"
        message += f"• New vulnerabilities: {new_vulns}\n"
        message += f"• Critical: {critical_count}\n"
        message += f"• High: {high_count}\n"
        
        if summary.get('new_findings'):
            message += f"\n🚨 New Critical/High Findings:\n"
            for finding in summary['new_findings'][:5]:  # Top 5
                if finding['severity'] in ['critical', 'high']:
                    message += f"• {finding['title']} ({finding['severity']}) - {finding['host']}\n"
        
        # TODO: Implement actual notification sending
        # This would integrate with Slack webhook, email SMTP, etc.
        logger.info(f"Would send notification: {message[:200]}...")
        
        notifications_sent.append({
            'type': 'daily_summary',
            'channels': ['slack'] if slack_enabled else [] + ['email'] if email_enabled else [],
            'message_preview': message[:100] + '...',
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return {
            'notifications_sent': len(notifications_sent),
            'notifications': notifications_sent
        }
        
    except Exception as e:
        logger.error(f"Error sending daily notifications: {str(e)}")
        return {'error': str(e)}


@flow(name="schedule-daily-scans")
def schedule_daily_scans_flow(domains: List[str], config_path: str = "config/default_config.yaml") -> Dict[str, Any]:
    """
    Schedule daily scans for multiple domains.
    
    Args:
        domains: List of domains to scan
        config_path: Path to configuration file
        
    Returns:
        Summary of all daily scans
    """
    logger = get_run_logger()
    logger.info(f"Scheduling daily scans for {len(domains)} domains")
    
    results = []
    
    for domain in domains:
        try:
            result = daily_incremental_scan_flow(domain, config_path)
            results.append(result)
        except Exception as e:
            logger.error(f"Daily scan failed for {domain}: {str(e)}")
            results.append({
                'domain': domain,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
    
    # Generate overall summary
    total_vulns = sum(
        result.get('summary', {}).get('total_vulnerabilities', 0) 
        for result in results if 'error' not in result
    )
    
    total_new_vulns = sum(
        result.get('summary', {}).get('new_vulnerabilities', 0)
        for result in results if 'error' not in result
    )
    
    failed_scans = len([r for r in results if 'error' in r])
    
    overall_summary = {
        'timestamp': datetime.utcnow().isoformat(),
        'total_domains': len(domains),
        'successful_scans': len(domains) - failed_scans,
        'failed_scans': failed_scans,
        'total_vulnerabilities': total_vulns,
        'total_new_vulnerabilities': total_new_vulns,
        'results': results
    }
    
    logger.info(f"Daily scan batch completed: {len(domains) - failed_scans}/{len(domains)} successful")
    
    return overall_summary


if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="Run daily incremental scan")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("--config", default="config/default_config.yaml", help="Config file path")
    
    args = parser.parse_args()
    
    result = daily_incremental_scan_flow(args.domain, args.config)
    print(f"Daily scan completed for {args.domain}")
    print(f"New vulnerabilities: {result['summary']['new_vulnerabilities']}")
    print(f"Total vulnerabilities: {result['summary']['total_vulnerabilities']}")