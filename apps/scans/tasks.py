"""
Scan orchestration for OpenEASD.

Phases:
  1. Apex domain security (DNS, SSL, email)
  2. Service detection (subfinder → naabu → nmap)
  3. Vulnerability assessment (nuclei)
  4. Update session totals
  5. Delta detection
  6. Alert dispatch
"""

import logging
import threading

from django.utils import timezone as django_tz

from .models import ScanSession, ScanDelta

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Delta detection
# ---------------------------------------------------------------------------

def _detect_deltas(session):
    previous = (
        ScanSession.objects.filter(domain=session.domain, status="completed")
        .exclude(id=session.id)
        .order_by("-start_time")
        .first()
    )
    if not previous:
        return

    # Subdomain deltas
    current_subs = set(session.subdomains.values_list("subdomain", flat=True))
    prev_subs = set(previous.subdomains.values_list("subdomain", flat=True))
    for sub in current_subs - prev_subs:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="new", change_category="subdomain", item_identifier=sub)
    for sub in prev_subs - current_subs:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="removed", change_category="subdomain", item_identifier=sub)

    # Port deltas
    current_ports = set(session.port_results.values_list("host", "port", "protocol"))
    prev_ports = set(previous.port_results.values_list("host", "port", "protocol"))
    for host, port, proto in current_ports - prev_ports:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="new", change_category="port",
                                 item_identifier=f"{host}:{port}/{proto}")
    for host, port, proto in prev_ports - current_ports:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="removed", change_category="port",
                                 item_identifier=f"{host}:{port}/{proto}")

    # Nuclei vulnerability deltas
    prev_nuclei_keys = {
        f"{v.host}:{v.template_id}" for v in previous.nuclei_findings.all()
    }
    for v in session.nuclei_findings.all():
        key = f"{v.host}:{v.template_id}"
        if key not in prev_nuclei_keys:
            ScanDelta.objects.create(session=session, previous_session=previous,
                                     change_type="new", change_category="vulnerability",
                                     item_identifier=key,
                                     change_details={"severity": v.severity, "title": v.template_name})


def _count_all_findings(session) -> int:
    total = 0
    try:
        total += session.nuclei_findings.count()
    except Exception:
        pass
    try:
        total += session.dns_findings.count()
    except Exception:
        pass
    try:
        total += session.ssl_findings.count()
    except Exception:
        pass
    try:
        total += session.email_findings.count()
    except Exception:
        pass
    return total


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(session_id: int):
    session = ScanSession.objects.select_related("workflow").get(id=session_id)
    domain = session.domain
    logger.info(f"[scan:{session_id}] Starting {session.scan_type} scan for {domain}")

    # If a workflow is attached, delegate to workflow runner
    if session.workflow_id:
        _run_via_workflow(session)
        return

    # Default pipeline (no workflow selected)
    try:
        # Phase 1: Apex domain security
        logger.info(f"[scan:{session_id}] Phase 1: Apex domain security")
        from apps.dns_analyzer.scanner import run_dns_analysis
        from apps.ssl_checker.scanner import run_ssl_check
        from apps.email_security.scanner import run_email_check
        run_dns_analysis(session)
        run_ssl_check(session)
        run_email_check(session)

        # Phase 2: Service detection
        logger.info(f"[scan:{session_id}] Phase 2: Service detection")
        from apps.subfinder.scanner import run_subfinder
        from apps.naabu.scanner import run_naabu
        from apps.nmap.scanner import run_nmap
        subdomains = run_subfinder(session)
        targets = [domain] + [s.subdomain for s in subdomains]
        run_naabu(session, targets)
        run_nmap(session, domain)

        # Phase 3: Vulnerability assessment
        logger.info(f"[scan:{session_id}] Phase 3: Vulnerability scanning")
        from apps.nuclei.scanner import run_nuclei
        run_nuclei(session, targets)

        # Phase 4: Update session totals
        total = _count_all_findings(session)
        session.total_findings = total
        session.status = "completed"
        session.end_time = django_tz.now()
        session.save(update_fields=["total_findings", "status", "end_time"])
        logger.info(f"[scan:{session_id}] Completed with {total} total findings")

        # Phase 5: Delta detection
        logger.info(f"[scan:{session_id}] Phase 5: Delta detection")
        _detect_deltas(session)

        # Phase 6: Alert dispatch
        logger.info(f"[scan:{session_id}] Phase 6: Alert dispatch")
        from apps.alerts.dispatcher import dispatch_alerts
        dispatch_alerts(session_id)

    except Exception as exc:
        logger.error(f"[scan:{session_id}] Scan failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])


def _run_via_workflow(session):
    """Run scan using a Workflow definition, then finalize the session."""
    session_id = session.id
    from apps.workflow.models import WorkflowRun
    from apps.workflow.runner import run_workflow

    run = WorkflowRun.objects.create(workflow=session.workflow, session=session)
    try:
        run_workflow(run.id)

        total = _count_all_findings(session)
        session.total_findings = total
        session.status = "completed" if run.status == "completed" else "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["total_findings", "status", "end_time"])

        if session.status == "completed":
            _detect_deltas(session)
            from apps.alerts.dispatcher import dispatch_alerts
            dispatch_alerts(session_id)

    except Exception as exc:
        logger.error(f"[scan:{session_id}] Workflow run failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])


# ---------------------------------------------------------------------------
# Scheduled scan functions
# ---------------------------------------------------------------------------

def daily_scan():
    from apps.core.models import ScanConfiguration

    active_configs = ScanConfiguration.objects.filter(is_active=True)
    if not active_configs.exists():
        logger.info("[daily_scan] No active domain configurations found")
        return

    for cfg in active_configs:
        session = ScanSession.objects.create(domain=cfg.domain, scan_type="incremental")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[daily_scan] Launched scan for {cfg.domain} (session {session.id})")


def weekly_scan():
    from apps.core.models import ScanConfiguration

    active_configs = ScanConfiguration.objects.filter(is_active=True)
    if not active_configs.exists():
        logger.info("[weekly_scan] No active domain configurations found")
        return

    for cfg in active_configs:
        session = ScanSession.objects.create(domain=cfg.domain, scan_type="full")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[weekly_scan] Launched full scan for {cfg.domain} (session {session.id})")
