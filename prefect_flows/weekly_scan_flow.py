"""Weekly full scan flow for OpenEASD."""

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.orchestrator import ScanOrchestrator
from core.config_manager import ConfigManager
from core.database import DatabaseManager
from utils.mitre_mapper import MITREMapper
from utils.result_parser import ResultParser


@flow(
    name="openeasd-weekly-full-scan",
    task_runner=ConcurrentTaskRunner(),
    description="Weekly comprehensive security scan for OpenEASD"
)
def weekly_full_scan_flow(domain: str, config_path: str = "config/default_config.yaml") -> Dict[str, Any]:
    """
    Execute weekly comprehensive security scan.
    
    Args:
        domain: Target domain to scan
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing comprehensive scan results
    """
    logger = get_run_logger()
    logger.info(f"Starting weekly full scan for domain: {domain}")
    
    try:
        # Initialize orchestrator
        orchestrator = ScanOrchestrator(config_path)
        
        # Execute full scan
        scan_results = orchestrator.security_scan_flow(domain, scan_type="full")
        
        # Generate comprehensive analysis
        analysis = generate_comprehensive_analysis.submit(scan_results)
        
        # Generate MITRE ATT&CK mapping
        mitre_analysis = generate_mitre_analysis.submit(scan_results)
        
        # Generate trend analysis
        trend_analysis = generate_trend_analysis.submit(domain, scan_results)
        
        # Generate weekly report
        weekly_report = generate_weekly_report.submit(
            scan_results, analysis, mitre_analysis, trend_analysis
        )
        
        # Send weekly notifications
        notification_result = send_weekly_notifications.submit(weekly_report)
        
        logger.info(f"Weekly full scan completed for {domain}")
        
        return {
            'scan_type': 'full',
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'scan_results': scan_results,
            'analysis': analysis.result(),
            'mitre_analysis': mitre_analysis.result(),
            'trend_analysis': trend_analysis.result(),
            'weekly_report': weekly_report.result(),
            'notifications_sent': notification_result.result()
        }
        
    except Exception as e:
        logger.error(f"Weekly full scan failed for {domain}: {str(e)}")
        raise


@task(name="generate-comprehensive-analysis")
def generate_comprehensive_analysis(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate comprehensive analysis of scan results."""
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
        
        # Parse and standardize results
        parser = ResultParser()
        
        # Vulnerability analysis
        severity_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        vulnerability_types = {}
        affected_hosts = set()
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            severity_distribution[severity] += 1
            
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
            
            host = vuln.get('host')
            if host:
                affected_hosts.add(host)
        
        # Service analysis
        service_distribution = {}
        high_risk_services = []
        open_ports = set()
        
        for service in services:
            service_name = service.get('service_name', 'unknown')
            service_distribution[service_name] = service_distribution.get(service_name, 0) + 1
            
            if service.get('risk_level') in ['high', 'critical']:
                high_risk_services.append({
                    'host': service.get('host'),
                    'port': service.get('port'),
                    'service': service_name,
                    'risk_level': service.get('risk_level')
                })
            
            port = service.get('port')
            if port:
                open_ports.add(port)
        
        # Subdomain analysis
        subdomain_sources = {}
        for subdomain in subdomains:
            source = subdomain.get('source', 'unknown')
            subdomain_sources[source] = subdomain_sources.get(source, 0) + 1
        
        # Attack surface calculation
        attack_surface_score = (
            len(subdomains) * 1 +           # Each subdomain adds to surface
            len(services) * 2 +             # Each service adds more risk
            len(high_risk_services) * 5 +   # High-risk services are critical
            len(affected_hosts) * 3         # Each affected host is significant
        )
        
        # Risk assessment
        total_vulns = len(vulnerabilities)
        critical_vulns = severity_distribution['critical']
        high_vulns = severity_distribution['high']
        
        if critical_vulns > 0:
            overall_risk = 'critical'
        elif high_vulns > 5 or (high_vulns > 0 and len(high_risk_services) > 0):
            overall_risk = 'high'
        elif high_vulns > 0 or total_vulns > 10:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        analysis = {
            'session_id': session_id,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'vulnerability_analysis': {
                'total_vulnerabilities': total_vulns,
                'severity_distribution': severity_distribution,
                'vulnerability_types': dict(sorted(vulnerability_types.items(), 
                                                  key=lambda x: x[1], reverse=True)[:10]),
                'affected_hosts_count': len(affected_hosts)
            },
            'service_analysis': {
                'total_services': len(services),
                'service_distribution': dict(sorted(service_distribution.items(),
                                                   key=lambda x: x[1], reverse=True)[:10]),
                'high_risk_services': high_risk_services,
                'unique_ports': sorted(list(open_ports)),
                'port_count': len(open_ports)
            },
            'subdomain_analysis': {
                'total_subdomains': len(subdomains),
                'subdomain_sources': subdomain_sources,
                'discovery_effectiveness': len(subdomains) / max(len(subdomain_sources), 1)
            },
            'attack_surface': {
                'score': attack_surface_score,
                'level': 'high' if attack_surface_score > 50 else 'medium' if attack_surface_score > 20 else 'low',
                'contributing_factors': {
                    'subdomain_count': len(subdomains),
                    'service_count': len(services),
                    'high_risk_services': len(high_risk_services),
                    'affected_hosts': len(affected_hosts)
                }
            },
            'overall_risk_assessment': {
                'risk_level': overall_risk,
                'risk_score': attack_surface_score,
                'key_risks': generate_key_risks(severity_distribution, high_risk_services, vulnerability_types)
            }
        }
        
        logger.info(f"Comprehensive analysis completed: {total_vulns} vulnerabilities, "
                   f"{len(services)} services, {len(subdomains)} subdomains")
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error generating comprehensive analysis: {str(e)}")
        return {'error': str(e)}


@task(name="generate-mitre-analysis")
def generate_mitre_analysis(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate MITRE ATT&CK analysis of vulnerabilities."""
    logger = get_run_logger()
    
    try:
        session_id = scan_results.get('session_id')
        if not session_id:
            return {'error': 'No session ID found in scan results'}
        
        # Get vulnerabilities from database
        db = DatabaseManager()
        vulnerabilities = db.get_vulnerabilities(session_id)
        
        # Initialize MITRE mapper
        mitre_mapper = MITREMapper()
        
        # Generate MITRE analysis
        mitre_report = mitre_mapper.export_mitre_report(vulnerabilities)
        
        logger.info(f"MITRE analysis completed: {len(vulnerabilities)} vulnerabilities mapped")
        
        return mitre_report
        
    except Exception as e:
        logger.error(f"Error generating MITRE analysis: {str(e)}")
        return {'error': str(e)}


@task(name="generate-trend-analysis")
def generate_trend_analysis(domain: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate trend analysis comparing with historical data."""
    logger = get_run_logger()
    
    try:
        db = DatabaseManager()
        
        # Get historical statistics
        stats_30_days = db.get_scan_statistics(domain, 30)
        stats_90_days = db.get_scan_statistics(domain, 90)
        
        # Get change trends
        from core.delta_detector import DeltaDetector
        delta_detector = DeltaDetector(db)
        change_trends = delta_detector.get_change_trends(domain, 30)
        
        current_session_id = scan_results.get('session_id')
        current_vulns = len(db.get_vulnerabilities(current_session_id)) if current_session_id else 0
        current_services = len(db.get_services(current_session_id)) if current_session_id else 0
        current_subdomains = len(db.get_subdomains(current_session_id)) if current_session_id else 0
        
        # Calculate trends
        avg_vulns_30d = stats_30_days.get('avg_findings', 0) or 0
        avg_vulns_90d = stats_90_days.get('avg_findings', 0) or 0
        
        vuln_trend = 'stable'
        if current_vulns > avg_vulns_30d * 1.2:
            vuln_trend = 'increasing'
        elif current_vulns < avg_vulns_30d * 0.8:
            vuln_trend = 'decreasing'
        
        analysis = {
            'domain': domain,
            'analysis_date': datetime.utcnow().isoformat(),
            'current_metrics': {
                'vulnerabilities': current_vulns,
                'services': current_services,
                'subdomains': current_subdomains
            },
            'historical_comparison': {
                '30_day_average_vulnerabilities': avg_vulns_30d,
                '90_day_average_vulnerabilities': avg_vulns_90d,
                'vulnerability_trend': vuln_trend,
                'scan_reliability_30d': stats_30_days.get('successful_scans', 0) / max(stats_30_days.get('total_scans', 1), 1) * 100
            },
            'change_trends': change_trends,
            'recommendations': generate_trend_recommendations(vuln_trend, change_trends, stats_30_days)
        }
        
        logger.info(f"Trend analysis completed for {domain}: {vuln_trend} vulnerability trend")
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error generating trend analysis: {str(e)}")
        return {'error': str(e)}


@task(name="generate-weekly-report")
def generate_weekly_report(scan_results: Dict[str, Any], analysis: Dict[str, Any],
                          mitre_analysis: Dict[str, Any], trend_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Generate comprehensive weekly security report."""
    logger = get_run_logger()
    
    try:
        domain = scan_results.get('domain', 'Unknown')
        
        # Executive summary
        vuln_analysis = analysis.get('vulnerability_analysis', {})
        total_vulns = vuln_analysis.get('total_vulnerabilities', 0)
        critical_vulns = vuln_analysis.get('severity_distribution', {}).get('critical', 0)
        high_vulns = vuln_analysis.get('severity_distribution', {}).get('high', 0)
        
        executive_summary = f"""
Weekly Security Assessment Report for {domain}

EXECUTIVE SUMMARY:
• Total Vulnerabilities: {total_vulns}
• Critical Issues: {critical_vulns}
• High Severity Issues: {high_vulns}
• Overall Risk Level: {analysis.get('overall_risk_assessment', {}).get('risk_level', 'Unknown').title()}
• Attack Surface Score: {analysis.get('attack_surface', {}).get('score', 0)}

KEY FINDINGS:
"""
        
        # Add top vulnerabilities
        top_vulns = vuln_analysis.get('vulnerability_types', {})
        for i, (vuln_type, count) in enumerate(list(top_vulns.items())[:5], 1):
            executive_summary += f"• {i}. {vuln_type.replace('_', ' ').title()}: {count} instances\n"
        
        # Add MITRE insights
        attack_analysis = mitre_analysis.get('attack_analysis', {})
        tactic_counts = attack_analysis.get('tactic_counts', {})
        if tactic_counts:
            executive_summary += f"\nATTACK VECTOR ANALYSIS:\n"
            for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                executive_summary += f"• {tactic.replace('-', ' ').title()}: {count} techniques\n"
        
        # Generate report
        report = {
            'report_metadata': {
                'domain': domain,
                'report_type': 'weekly_comprehensive',
                'generated_at': datetime.utcnow().isoformat(),
                'report_period': f"{(datetime.utcnow() - timedelta(days=7)).date()} to {datetime.utcnow().date()}",
                'scan_session_id': scan_results.get('session_id')
            },
            'executive_summary': executive_summary,
            'detailed_analysis': analysis,
            'mitre_attack_analysis': mitre_analysis,
            'trend_analysis': trend_analysis,
            'recommendations': compile_recommendations(analysis, mitre_analysis, trend_analysis),
            'next_actions': generate_next_actions(analysis, critical_vulns, high_vulns)
        }
        
        logger.info(f"Weekly report generated for {domain}")
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating weekly report: {str(e)}")
        return {'error': str(e)}


@task(name="send-weekly-notifications")
def send_weekly_notifications(weekly_report: Dict[str, Any]) -> Dict[str, Any]:
    """Send weekly report notifications."""
    logger = get_run_logger()
    
    try:
        config = ConfigManager()
        
        # Check notification settings
        slack_enabled = config.is_alert_enabled('slack')
        email_enabled = config.is_alert_enabled('email')
        
        if not slack_enabled and not email_enabled:
            logger.info("No notification channels enabled for weekly report")
            return {'notifications_sent': 0}
        
        # Prepare summary message
        domain = weekly_report.get('report_metadata', {}).get('domain', 'Unknown')
        analysis = weekly_report.get('detailed_analysis', {})
        
        total_vulns = analysis.get('vulnerability_analysis', {}).get('total_vulnerabilities', 0)
        critical_vulns = analysis.get('vulnerability_analysis', {}).get('severity_distribution', {}).get('critical', 0)
        high_vulns = analysis.get('vulnerability_analysis', {}).get('severity_distribution', {}).get('high', 0)
        risk_level = analysis.get('overall_risk_assessment', {}).get('risk_level', 'unknown')
        
        message = f"📊 Weekly Security Report - {domain}\n\n"
        message += f"🎯 Overall Risk Level: {risk_level.upper()}\n\n"
        message += f"📈 Key Metrics:\n"
        message += f"• Total Vulnerabilities: {total_vulns}\n"
        message += f"• Critical: {critical_vulns}\n"
        message += f"• High: {high_vulns}\n"
        message += f"• Attack Surface Score: {analysis.get('attack_surface', {}).get('score', 0)}\n\n"
        
        # Add trend information
        trend_analysis = weekly_report.get('trend_analysis', {})
        vuln_trend = trend_analysis.get('historical_comparison', {}).get('vulnerability_trend', 'stable')
        message += f"📊 Trend: Vulnerabilities are {vuln_trend}\n\n"
        
        # Add top recommendations
        recommendations = weekly_report.get('recommendations', [])
        if recommendations:
            message += f"🔧 Top Recommendations:\n"
            for i, rec in enumerate(recommendations[:3], 1):
                message += f"{i}. {rec}\n"
        
        # TODO: Implement actual notification sending
        logger.info(f"Would send weekly report notification: {message[:200]}...")
        
        return {
            'notifications_sent': 1,
            'message_preview': message[:200] + '...',
            'full_report_available': True
        }
        
    except Exception as e:
        logger.error(f"Error sending weekly notifications: {str(e)}")
        return {'error': str(e)}


def generate_key_risks(severity_dist: Dict[str, int], high_risk_services: List[Dict],
                      vuln_types: Dict[str, int]) -> List[str]:
    """Generate list of key risks."""
    risks = []
    
    if severity_dist.get('critical', 0) > 0:
        risks.append(f"{severity_dist['critical']} critical vulnerabilities require immediate attention")
    
    if len(high_risk_services) > 0:
        risks.append(f"{len(high_risk_services)} high-risk services exposed")
    
    # Check for specific high-risk vulnerability types
    high_risk_types = ['sql_injection', 'remote_code_execution', 'authentication_bypass', 'exposed_database']
    for vuln_type in high_risk_types:
        if vuln_type in vuln_types:
            risks.append(f"{vuln_types[vuln_type]} {vuln_type.replace('_', ' ')} vulnerabilities found")
    
    return risks


def generate_trend_recommendations(vuln_trend: str, change_trends: Dict, stats: Dict) -> List[str]:
    """Generate recommendations based on trends."""
    recommendations = []
    
    if vuln_trend == 'increasing':
        recommendations.append("Vulnerability count is increasing - review security practices")
    
    total_changes = change_trends.get('total_changes', 0)
    if total_changes > 10:
        recommendations.append("High rate of infrastructure changes detected - monitor for unauthorized modifications")
    
    scan_reliability = stats.get('successful_scans', 0) / max(stats.get('total_scans', 1), 1) * 100
    if scan_reliability < 90:
        recommendations.append(f"Scan reliability is {scan_reliability:.1f}% - investigate scan failures")
    
    return recommendations


def compile_recommendations(analysis: Dict, mitre_analysis: Dict, trend_analysis: Dict) -> List[str]:
    """Compile all recommendations from different analyses."""
    recommendations = []
    
    # From analysis
    risk_assessment = analysis.get('overall_risk_assessment', {})
    key_risks = risk_assessment.get('key_risks', [])
    recommendations.extend(key_risks)
    
    # From MITRE analysis
    mitre_recs = mitre_analysis.get('attack_analysis', {}).get('risk_assessment', {}).get('recommendations', [])
    recommendations.extend(mitre_recs)
    
    # From trend analysis
    trend_recs = trend_analysis.get('recommendations', [])
    recommendations.extend(trend_recs)
    
    # Remove duplicates and return top 10
    unique_recs = list(dict.fromkeys(recommendations))
    return unique_recs[:10]


def generate_next_actions(analysis: Dict, critical_vulns: int, high_vulns: int) -> List[str]:
    """Generate specific next actions based on findings."""
    actions = []
    
    if critical_vulns > 0:
        actions.append("URGENT: Address all critical vulnerabilities within 24 hours")
    
    if high_vulns > 0:
        actions.append(f"HIGH PRIORITY: Remediate {high_vulns} high-severity vulnerabilities within 72 hours")
    
    high_risk_services = analysis.get('service_analysis', {}).get('high_risk_services', [])
    if len(high_risk_services) > 0:
        actions.append(f"Review and secure {len(high_risk_services)} high-risk services")
    
    attack_surface_score = analysis.get('attack_surface', {}).get('score', 0)
    if attack_surface_score > 50:
        actions.append("Consider attack surface reduction - disable unnecessary services")
    
    actions.append("Schedule next incremental scan for tomorrow")
    actions.append("Review and update security monitoring rules")
    
    return actions


if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="Run weekly full scan")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("--config", default="config/default_config.yaml", help="Config file path")
    
    args = parser.parse_args()
    
    result = weekly_full_scan_flow(args.domain, args.config)
    print(f"Weekly scan completed for {args.domain}")
    print(f"Overall risk level: {result['analysis']['overall_risk_assessment']['risk_level']}")
    print(f"Total vulnerabilities: {result['analysis']['vulnerability_analysis']['total_vulnerabilities']}")