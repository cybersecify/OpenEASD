"""
Scan orchestration functions for OpenEASD.

Phases:
  1. Apex domain security (DNS, SSL, email security)
  2. Service detection (Subfinder → Naabu → Nmap)
  3. Web vulnerability assessment (Nuclei)
  4. Result persistence
  5. Delta detection
  6. Alert dispatch
"""

import logging
import sys

from django.conf import settings
from django.utils import timezone as django_tz

from .models import ScanSession, Subdomain, Service, Vulnerability, Alert, ScanDelta

sys.path.insert(0, str(settings.BASE_DIR))

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_config():
    try:
        from src.core.config_manager import ConfigManager
        return ConfigManager()
    except Exception as e:
        logger.warning(f"ConfigManager unavailable, using defaults: {e}")
        return None


def _save_subdomains(session, subdomains: list[dict]):
    objs = [
        Subdomain(
            session=session,
            subdomain=s.get("subdomain", s.get("host", "")),
            ip_address=s.get("ip_address") or None,
        )
        for s in subdomains
        if s.get("subdomain") or s.get("host")
    ]
    Subdomain.objects.bulk_create(objs, ignore_conflicts=True)


def _save_services(session, services: list[dict]):
    objs = [
        Service(
            session=session,
            host=s.get("host", ""),
            port=int(s.get("port", 0)),
            service_name=s.get("service_name", ""),
            version=s.get("version", ""),
            protocol=s.get("protocol", "tcp"),
            state=s.get("state", "open"),
            risk_level=s.get("risk_level", "low"),
        )
        for s in services
        if s.get("host") and s.get("port")
    ]
    Service.objects.bulk_create(objs, ignore_conflicts=True)


def _save_vulnerabilities(session, vulns: list[dict]) -> list[Vulnerability]:
    saved = []
    for v in vulns:
        obj = Vulnerability.objects.create(
            session=session,
            host=v.get("host", ""),
            port=v.get("port"),
            vulnerability_type=v.get("vulnerability_type", "unknown"),
            severity=v.get("severity", "low"),
            title=v.get("title", ""),
            description=v.get("description", ""),
            remediation=v.get("remediation", ""),
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id", ""),
            mitre_technique=v.get("mitre_technique", ""),
            confidence=v.get("confidence", "medium"),
        )
        saved.append(obj)
    return saved


def _detect_deltas(session):
    previous = (
        ScanSession.objects.filter(domain=session.domain, status="completed")
        .exclude(id=session.id)
        .order_by("-start_time")
        .first()
    )
    if not previous:
        return

    current_subs = set(session.subdomains.values_list("subdomain", flat=True))
    prev_subs = set(previous.subdomains.values_list("subdomain", flat=True))

    for sub in current_subs - prev_subs:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="new", change_category="subdomain", item_identifier=sub)
    for sub in prev_subs - current_subs:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="removed", change_category="subdomain", item_identifier=sub)

    current_svcs = set(session.services.values_list("host", "port", "protocol"))
    prev_svcs = set(previous.services.values_list("host", "port", "protocol"))
    for host, port, proto in current_svcs - prev_svcs:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="new", change_category="service",
                                 item_identifier=f"{host}:{port}/{proto}")
    for host, port, proto in prev_svcs - current_svcs:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="removed", change_category="service",
                                 item_identifier=f"{host}:{port}/{proto}")

    prev_vuln_keys = {f"{v.host}:{v.vulnerability_type}" for v in previous.vulnerabilities.all()}
    for v in session.vulnerabilities.all():
        key = f"{v.host}:{v.vulnerability_type}"
        if key not in prev_vuln_keys:
            ScanDelta.objects.create(session=session, previous_session=previous,
                                     change_type="new", change_category="vulnerability",
                                     item_identifier=key,
                                     change_details={"severity": v.severity, "title": v.title})


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def run_scan(session_id: int):
    session = ScanSession.objects.get(id=session_id)
    domain = session.domain
    logger.info(f"[scan:{session_id}] Starting {session.scan_type} scan for {domain}")

    try:
        all_subdomains: list[dict] = []
        all_services: list[dict] = []
        all_vulns: list[dict] = []

        # Phase 1: Apex domain security
        logger.info(f"[scan:{session_id}] Phase 1: Apex domain security")
        try:
            from src.modules.apex_domain_security.dns_analyzer import DNSAnalyzer
            from src.modules.apex_domain_security.ssl_checker import SSLChecker
            from src.modules.apex_domain_security.email_security import EmailSecurity

            dns_result = DNSAnalyzer().dns_record_analysis(domain)
            if dns_result.get("vulnerabilities"):
                all_vulns.extend(dns_result["vulnerabilities"])

            ssl_result = SSLChecker().ssl_certificate_validation(domain)
            if ssl_result.get("vulnerabilities"):
                all_vulns.extend(ssl_result["vulnerabilities"])

            email_result = EmailSecurity().spf_dmarc_checker(domain)
            if email_result.get("vulnerabilities"):
                all_vulns.extend(email_result["vulnerabilities"])
        except Exception as e:
            logger.warning(f"[scan:{session_id}] Apex domain security partial failure: {e}")

        # Phase 2: Service detection
        logger.info(f"[scan:{session_id}] Phase 2: Service detection")
        targets = [domain]
        try:
            from src.utils.tool_wrapper import SubfinderWrapper, NaabuWrapper, NmapWrapper
            from src.utils.result_parser import ResultParser

            parser = ResultParser()
            subfinder_result = SubfinderWrapper().enumerate_subdomains(domain)
            parsed_subs = parser.parse_subfinder_output(subfinder_result.get("raw_output", ""), domain)
            all_subdomains.extend(parsed_subs)
            targets = [domain] + [s.get("subdomain", "") for s in parsed_subs if s.get("subdomain")]

            naabu_result = NaabuWrapper().scan_ports(targets)
            parser.parse_naabu_output(naabu_result.get("raw_output", ""))

            nmap_result = NmapWrapper().service_scan(domain)
            parsed_services = parser.parse_nmap_xml(nmap_result.get("raw_output", ""))
            all_services.extend(parsed_services)
        except Exception as e:
            logger.warning(f"[scan:{session_id}] Service detection partial failure: {e}")

        # Phase 3: Vulnerability assessment
        logger.info(f"[scan:{session_id}] Phase 3: Vulnerability scanning")
        try:
            from src.utils.tool_wrapper import NucleiWrapper
            from src.utils.result_parser import ResultParser

            parser = ResultParser()
            nuclei_result = NucleiWrapper().vulnerability_scan(targets)
            parsed_vulns = parser.parse_nuclei_output(nuclei_result.get("raw_output", ""))
            all_vulns.extend(parsed_vulns)
        except Exception as e:
            logger.warning(f"[scan:{session_id}] Nuclei scanning partial failure: {e}")

        # Phase 4: Persist results
        logger.info(f"[scan:{session_id}] Phase 4: Persisting results")
        _save_subdomains(session, all_subdomains)
        _save_services(session, all_services)
        _save_vulnerabilities(session, all_vulns)

        session.total_findings = len(all_vulns)
        session.status = "completed"
        session.end_time = django_tz.now()
        session.save(update_fields=["total_findings", "status", "end_time"])
        logger.info(f"[scan:{session_id}] Completed: {len(all_subdomains)} subdomains, "
                    f"{len(all_services)} services, {len(all_vulns)} vulnerabilities")

        # Phase 5: Delta detection
        logger.info(f"[scan:{session_id}] Phase 5: Delta detection")
        _detect_deltas(session)

        # Phase 6: Alert dispatch
        logger.info(f"[scan:{session_id}] Phase 6: Alert dispatch")
        dispatch_alerts(session_id)

    except Exception as exc:
        logger.error(f"[scan:{session_id}] Scan failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])

    return {"session_id": session_id, "total_findings": session.total_findings}


# ---------------------------------------------------------------------------
# Alert dispatch
# ---------------------------------------------------------------------------

def dispatch_alerts(session_id: int, severity_threshold: str = "high"):
    session = ScanSession.objects.get(id=session_id)
    threshold_level = SEVERITY_ORDER.get(severity_threshold, 3)

    qualifying = [
        v for v in session.vulnerabilities.all()
        if SEVERITY_ORDER.get(v.severity, 0) >= threshold_level
    ]

    if not qualifying:
        logger.info(f"[alerts:{session_id}] No vulnerabilities above {severity_threshold} threshold")
        return

    grouped: dict[str, list] = {}
    for v in qualifying:
        grouped.setdefault(v.severity, []).append(v)

    lines = [
        f"*OpenEASD Security Alert* — {session.domain}",
        f"Scan #{session_id} | {django_tz.now().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    for sev in ["critical", "high", "medium", "low"]:
        if sev in grouped:
            lines.append(f"*{sev.upper()}* ({len(grouped[sev])} findings)")
            for v in grouped[sev][:5]:
                lines.append(f"  • {v.title or v.vulnerability_type} @ {v.host}")
            if len(grouped[sev]) > 5:
                lines.append(f"  … and {len(grouped[sev]) - 5} more")
            lines.append("")

    full_message = "\n".join(lines)
    slack_url = settings.SLACK_WEBHOOK_URL
    alert_status = "pending"
    error_msg = ""

    if slack_url:
        try:
            import httpx
            resp = httpx.post(slack_url, json={"text": full_message}, timeout=10)
            resp.raise_for_status()
            alert_status = "sent"
            logger.info(f"[alerts:{session_id}] Slack alert sent")
        except Exception as e:
            alert_status = "failed"
            error_msg = str(e)
            logger.error(f"[alerts:{session_id}] Slack alert failed: {e}")

    Alert.objects.create(
        session=session,
        alert_type="slack",
        severity_threshold=severity_threshold,
        message=full_message,
        status=alert_status,
        error_message=error_msg,
    )

    return {"session_id": session_id, "alerts_sent": len(qualifying), "status": alert_status}


# ---------------------------------------------------------------------------
# Scheduled scan functions (called by management commands or cron)
# ---------------------------------------------------------------------------

def daily_scan():
    from apps.core.models import ScanConfiguration
    import threading

    active_configs = ScanConfiguration.objects.filter(is_active=True)
    if not active_configs.exists():
        logger.info("[daily_scan] No active domain configurations found")
        return {"launched": []}

    launched = []
    for cfg in active_configs:
        session = ScanSession.objects.create(domain=cfg.domain, scan_type="incremental")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        launched.append(cfg.domain)
        logger.info(f"[daily_scan] Launched incremental scan for {cfg.domain} (session {session.id})")

    return {"launched": launched}


def weekly_scan():
    from apps.core.models import ScanConfiguration
    import threading

    active_configs = ScanConfiguration.objects.filter(is_active=True)
    if not active_configs.exists():
        logger.info("[weekly_scan] No active domain configurations found")
        return {"launched": []}

    launched = []
    for cfg in active_configs:
        session = ScanSession.objects.create(domain=cfg.domain, scan_type="full")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        launched.append(cfg.domain)
        logger.info(f"[weekly_scan] Launched full scan for {cfg.domain} (session {session.id})")

    return {"launched": launched}
