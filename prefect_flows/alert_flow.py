"""Real-time alerting flow for OpenEASD."""

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.config_manager import ConfigManager
from core.database import DatabaseManager


@flow(
    name="openeasd-alert-processing",
    task_runner=ConcurrentTaskRunner(),
    description="Real-time alert processing and notification flow"
)
def alert_processing_flow(session_id: int, config_path: str = "config/default_config.yaml") -> Dict[str, Any]:
    """
    Process and send alerts for scan findings.
    
    Args:
        session_id: Scan session ID to process alerts for
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing alert processing results
    """
    logger = get_run_logger()
    logger.info(f"Starting alert processing for session {session_id}")
    
    try:
        # Load configuration
        config = ConfigManager(config_path)
        
        # Filter vulnerabilities that meet alert criteria
        alert_worthy_vulns = filter_alert_worthy_vulnerabilities.submit(session_id, config.get_dict())
        
        # Process different alert types in parallel
        slack_alerts = process_slack_alerts.submit(alert_worthy_vulns, config.get_dict())
        email_alerts = process_email_alerts.submit(alert_worthy_vulns, config.get_dict())
        webhook_alerts = process_webhook_alerts.submit(alert_worthy_vulns, config.get_dict())
        
        # Update alert status in database
        update_results = update_alert_status.submit(
            session_id, slack_alerts, email_alerts, webhook_alerts
        )
        
        logger.info(f"Alert processing completed for session {session_id}")
        
        return {
            'session_id': session_id,
            'timestamp': datetime.utcnow().isoformat(),
            'alert_worthy_vulnerabilities': len(alert_worthy_vulns.result()),
            'slack_alerts': slack_alerts.result(),
            'email_alerts': email_alerts.result(),
            'webhook_alerts': webhook_alerts.result(),
            'update_results': update_results.result()
        }
        
    except Exception as e:
        logger.error(f"Alert processing failed for session {session_id}: {str(e)}")
        raise


@task(name="filter-alert-worthy-vulnerabilities")
def filter_alert_worthy_vulnerabilities(session_id: int, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Filter vulnerabilities that meet alert criteria."""
    logger = get_run_logger()
    
    try:
        db = DatabaseManager()
        vulnerabilities = db.get_vulnerabilities(session_id)
        
        # Get alert configurations
        alert_config = config.get('alerts', {})
        
        alert_worthy = []
        
        # Process each alert type
        for alert_type in ['slack', 'email', 'webhook']:
            if not alert_config.get(alert_type, {}).get('enabled', False):
                continue
            
            threshold = alert_config[alert_type].get('severity_threshold', 'medium')
            
            # Define severity order for filtering
            severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            threshold_level = severity_order.get(threshold, 2)
            
            type_vulns = [
                {**vuln, 'alert_type': alert_type}
                for vuln in vulnerabilities
                if severity_order.get(vuln.get('severity', 'medium'), 2) >= threshold_level
            ]
            
            alert_worthy.extend(type_vulns)
        
        # Remove duplicates while preserving alert types
        unique_vulns = {}
        for vuln in alert_worthy:
            vuln_id = vuln.get('id')
            if vuln_id not in unique_vulns:
                unique_vulns[vuln_id] = vuln
                unique_vulns[vuln_id]['alert_types'] = [vuln['alert_type']]
            else:
                if vuln['alert_type'] not in unique_vulns[vuln_id]['alert_types']:
                    unique_vulns[vuln_id]['alert_types'].append(vuln['alert_type'])
        
        result = list(unique_vulns.values())
        
        logger.info(f"Filtered {len(result)} alert-worthy vulnerabilities from {len(vulnerabilities)} total")
        
        return result
        
    except Exception as e:
        logger.error(f"Error filtering alert-worthy vulnerabilities: {str(e)}")
        return []


@task(name="process-slack-alerts")
def process_slack_alerts(vulnerabilities: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """Process Slack alerts for vulnerabilities."""
    logger = get_run_logger()
    
    try:
        slack_config = config.get('alerts', {}).get('slack', {})
        
        if not slack_config.get('enabled', False):
            logger.info("Slack alerts not enabled")
            return {'enabled': False, 'alerts_sent': 0}
        
        webhook_url = slack_config.get('webhook_url')
        if not webhook_url:
            logger.warning("Slack webhook URL not configured")
            return {'enabled': True, 'alerts_sent': 0, 'error': 'No webhook URL configured'}
        
        # Filter vulnerabilities for Slack
        slack_vulns = [v for v in vulnerabilities if 'slack' in v.get('alert_types', [])]
        
        if not slack_vulns:
            logger.info("No vulnerabilities meet Slack alert criteria")
            return {'enabled': True, 'alerts_sent': 0}
        
        # Group vulnerabilities by severity for better presentation
        severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for vuln in slack_vulns:
            severity = vuln.get('severity', 'medium')
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
        
        # Prepare Slack message
        message = prepare_slack_message(severity_groups, config.get('target', {}).get('primary_domain', 'Unknown'))
        
        # Send to Slack (simulated - would use actual webhook in production)
        success = send_slack_message(webhook_url, message)
        
        alerts_sent = len(slack_vulns) if success else 0
        
        logger.info(f"Processed {alerts_sent} Slack alerts")
        
        return {
            'enabled': True,
            'alerts_sent': alerts_sent,
            'success': success,
            'message_preview': message['text'][:100] + '...' if success else None
        }
        
    except Exception as e:
        logger.error(f"Error processing Slack alerts: {str(e)}")
        return {'enabled': True, 'alerts_sent': 0, 'error': str(e)}


@task(name="process-email-alerts")
def process_email_alerts(vulnerabilities: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """Process email alerts for vulnerabilities."""
    logger = get_run_logger()
    
    try:
        email_config = config.get('alerts', {}).get('email', {})
        
        if not email_config.get('enabled', False):
            logger.info("Email alerts not enabled")
            return {'enabled': False, 'alerts_sent': 0}
        
        # Check email configuration
        required_fields = ['smtp_server', 'username', 'password', 'to_addresses']
        missing_fields = [field for field in required_fields if not email_config.get(field)]
        
        if missing_fields:
            logger.warning(f"Email configuration incomplete: missing {missing_fields}")
            return {'enabled': True, 'alerts_sent': 0, 'error': f'Missing configuration: {missing_fields}'}
        
        # Filter vulnerabilities for email
        email_vulns = [v for v in vulnerabilities if 'email' in v.get('alert_types', [])]
        
        if not email_vulns:
            logger.info("No vulnerabilities meet email alert criteria")
            return {'enabled': True, 'alerts_sent': 0}
        
        # Prepare email content
        email_content = prepare_email_content(email_vulns, config.get('target', {}).get('primary_domain', 'Unknown'))
        
        # Send email (simulated - would use actual SMTP in production)
        success = send_email_alert(email_config, email_content)
        
        alerts_sent = len(email_vulns) if success else 0
        
        logger.info(f"Processed {alerts_sent} email alerts")
        
        return {
            'enabled': True,
            'alerts_sent': alerts_sent,
            'success': success,
            'recipients': len(email_config.get('to_addresses', []))
        }
        
    except Exception as e:
        logger.error(f"Error processing email alerts: {str(e)}")
        return {'enabled': True, 'alerts_sent': 0, 'error': str(e)}


@task(name="process-webhook-alerts")
def process_webhook_alerts(vulnerabilities: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """Process webhook alerts for vulnerabilities."""
    logger = get_run_logger()
    
    try:
        webhook_config = config.get('alerts', {}).get('webhook', {})
        
        if not webhook_config.get('enabled', False):
            logger.info("Webhook alerts not enabled")
            return {'enabled': False, 'alerts_sent': 0}
        
        webhook_url = webhook_config.get('url')
        if not webhook_url:
            logger.warning("Webhook URL not configured")
            return {'enabled': True, 'alerts_sent': 0, 'error': 'No webhook URL configured'}
        
        # Filter vulnerabilities for webhook
        webhook_vulns = [v for v in vulnerabilities if 'webhook' in v.get('alert_types', [])]
        
        if not webhook_vulns:
            logger.info("No vulnerabilities meet webhook alert criteria")
            return {'enabled': True, 'alerts_sent': 0}
        
        # Prepare webhook payload
        payload = prepare_webhook_payload(webhook_vulns, config)
        
        # Send webhook (simulated - would make actual HTTP request in production)
        success = send_webhook_alert(webhook_url, payload, webhook_config.get('headers', {}))
        
        alerts_sent = len(webhook_vulns) if success else 0
        
        logger.info(f"Processed {alerts_sent} webhook alerts")
        
        return {
            'enabled': True,
            'alerts_sent': alerts_sent,
            'success': success,
            'webhook_url': webhook_url
        }
        
    except Exception as e:
        logger.error(f"Error processing webhook alerts: {str(e)}")
        return {'enabled': True, 'alerts_sent': 0, 'error': str(e)}


@task(name="update-alert-status")
def update_alert_status(session_id: int, slack_result: Dict, email_result: Dict, 
                       webhook_result: Dict) -> Dict[str, Any]:
    """Update alert status in database."""
    logger = get_run_logger()
    
    try:
        db = DatabaseManager()
        
        updates = []
        
        # Process Slack results
        if slack_result.get('enabled') and slack_result.get('alerts_sent', 0) > 0:
            # In production, this would update specific alert records
            updates.append({
                'type': 'slack',
                'count': slack_result['alerts_sent'],
                'status': 'sent' if slack_result.get('success') else 'failed'
            })
        
        # Process email results
        if email_result.get('enabled') and email_result.get('alerts_sent', 0) > 0:
            updates.append({
                'type': 'email',
                'count': email_result['alerts_sent'],
                'status': 'sent' if email_result.get('success') else 'failed'
            })
        
        # Process webhook results
        if webhook_result.get('enabled') and webhook_result.get('alerts_sent', 0) > 0:
            updates.append({
                'type': 'webhook',
                'count': webhook_result['alerts_sent'],
                'status': 'sent' if webhook_result.get('success') else 'failed'
            })
        
        # TODO: Update actual alert records in database
        # For now, just log the updates
        for update in updates:
            logger.info(f"Would update {update['count']} {update['type']} alerts as {update['status']}")
        
        total_sent = sum(update['count'] for update in updates if update['status'] == 'sent')
        total_failed = sum(update['count'] for update in updates if update['status'] == 'failed')
        
        return {
            'updates_processed': len(updates),
            'total_alerts_sent': total_sent,
            'total_alerts_failed': total_failed,
            'details': updates
        }
        
    except Exception as e:
        logger.error(f"Error updating alert status: {str(e)}")
        return {'error': str(e)}


def prepare_slack_message(severity_groups: Dict[str, List[Dict]], domain: str) -> Dict[str, Any]:
    """Prepare Slack message payload."""
    total_vulns = sum(len(vulns) for vulns in severity_groups.values())
    
    # Emoji mapping for severity
    severity_emojis = {
        'critical': '🚨',
        'high': '⚠️',
        'medium': '⚡',
        'low': 'ℹ️'
    }
    
    # Build message
    text = f"🔍 Security Alert for {domain}\n\n"
    text += f"Found {total_vulns} new security issue{'s' if total_vulns != 1 else ''} requiring attention:\n\n"
    
    for severity in ['critical', 'high', 'medium', 'low']:
        vulns = severity_groups[severity]
        if vulns:
            emoji = severity_emojis.get(severity, 'ℹ️')
            text += f"{emoji} *{severity.upper()}*: {len(vulns)} issue{'s' if len(vulns) != 1 else ''}\n"
            
            # Show top 3 vulnerabilities for this severity
            for vuln in vulns[:3]:
                host = vuln.get('host', 'Unknown')
                title = vuln.get('title', vuln.get('vulnerability_type', 'Unknown'))
                text += f"  • {title} on {host}\n"
            
            if len(vulns) > 3:
                text += f"  ... and {len(vulns) - 3} more\n"
            text += "\n"
    
    text += "Please review and remediate these security issues promptly."
    
    return {
        'text': text,
        'username': 'OpenEASD Security Scanner',
        'icon_emoji': ':shield:'
    }


def prepare_email_content(vulnerabilities: List[Dict[str, Any]], domain: str) -> Dict[str, Any]:
    """Prepare email content."""
    subject = f"Security Alert: {len(vulnerabilities)} vulnerabilities found for {domain}"
    
    # HTML content
    html_content = f"""
    <html>
    <body>
        <h2>Security Assessment Alert</h2>
        <p>Domain: <strong>{domain}</strong></p>
        <p>Scan Date: <strong>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</strong></p>
        
        <h3>Summary</h3>
        <p>Found <strong>{len(vulnerabilities)}</strong> security issues requiring attention.</p>
        
        <h3>Vulnerability Details</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f2f2f2;">
                <th>Severity</th>
                <th>Host</th>
                <th>Vulnerability</th>
                <th>Description</th>
            </tr>
    """
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'medium')
        host = vuln.get('host', 'Unknown')
        title = vuln.get('title', vuln.get('vulnerability_type', 'Unknown'))
        description = vuln.get('description', '')[:100] + '...' if len(vuln.get('description', '')) > 100 else vuln.get('description', '')
        
        severity_color = {
            'critical': '#ff4444',
            'high': '#ff8800',
            'medium': '#ffbb00',
            'low': '#00aa44'
        }.get(severity, '#666666')
        
        html_content += f"""
            <tr>
                <td style="color: {severity_color}; font-weight: bold;">{severity.upper()}</td>
                <td>{host}</td>
                <td>{title}</td>
                <td>{description}</td>
            </tr>
        """
    
    html_content += """
        </table>
        
        <h3>Recommendations</h3>
        <ul>
            <li>Review and prioritize vulnerabilities by severity</li>
            <li>Apply security patches and updates</li>
            <li>Implement recommended security configurations</li>
            <li>Monitor for exploitation attempts</li>
        </ul>
        
        <p><em>This alert was generated by OpenEASD Security Scanner</em></p>
    </body>
    </html>
    """
    
    # Plain text content
    text_content = f"""
Security Assessment Alert

Domain: {domain}
Scan Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

Summary:
Found {len(vulnerabilities)} security issues requiring attention.

Vulnerability Details:
"""
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'medium')
        host = vuln.get('host', 'Unknown')
        title = vuln.get('title', vuln.get('vulnerability_type', 'Unknown'))
        text_content += f"- {severity.upper()}: {title} on {host}\n"
    
    text_content += """
Recommendations:
- Review and prioritize vulnerabilities by severity
- Apply security patches and updates
- Implement recommended security configurations
- Monitor for exploitation attempts

This alert was generated by OpenEASD Security Scanner
"""
    
    return {
        'subject': subject,
        'html': html_content,
        'text': text_content
    }


def prepare_webhook_payload(vulnerabilities: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare webhook payload."""
    return {
        'event': 'security_alert',
        'timestamp': datetime.utcnow().isoformat(),
        'domain': config.get('target', {}).get('primary_domain', 'Unknown'),
        'alert_count': len(vulnerabilities),
        'vulnerabilities': [
            {
                'id': vuln.get('id'),
                'severity': vuln.get('severity'),
                'host': vuln.get('host'),
                'title': vuln.get('title'),
                'vulnerability_type': vuln.get('vulnerability_type'),
                'description': vuln.get('description'),
                'discovered_at': vuln.get('discovered_at')
            }
            for vuln in vulnerabilities
        ],
        'severity_summary': {
            severity: len([v for v in vulnerabilities if v.get('severity') == severity])
            for severity in ['critical', 'high', 'medium', 'low']
        }
    }


def send_slack_message(webhook_url: str, message: Dict[str, Any]) -> bool:
    """Send message to Slack (simulated)."""
    # In production, this would make an actual HTTP POST to the webhook URL
    # import requests
    # response = requests.post(webhook_url, json=message)
    # return response.status_code == 200
    
    # Simulated success
    return True


def send_email_alert(email_config: Dict[str, Any], content: Dict[str, Any]) -> bool:
    """Send email alert (simulated)."""
    # In production, this would use SMTP to send actual emails
    # import smtplib
    # from email.mime.multipart import MIMEMultipart
    # from email.mime.text import MIMEText
    
    # Simulated success
    return True


def send_webhook_alert(webhook_url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> bool:
    """Send webhook alert (simulated)."""
    # In production, this would make an actual HTTP POST
    # import requests
    # response = requests.post(webhook_url, json=payload, headers=headers)
    # return response.status_code == 200
    
    # Simulated success
    return True


if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="Process alerts for scan session")
    parser.add_argument("session_id", type=int, help="Scan session ID")
    parser.add_argument("--config", default="config/default_config.yaml", help="Config file path")
    
    args = parser.parse_args()
    
    result = alert_processing_flow(args.session_id, args.config)
    print(f"Alert processing completed for session {args.session_id}")
    print(f"Alert-worthy vulnerabilities: {result['alert_worthy_vulnerabilities']}")
    print(f"Alerts sent - Slack: {result['slack_alerts']['alerts_sent']}, Email: {result['email_alerts']['alerts_sent']}")