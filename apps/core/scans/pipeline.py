"""
Scan orchestration for OpenEASD.

All scans run through the workflow system — tools are defined as WorkflowSteps
in the database and executed dynamically by apps.core.workflows.runner.

The default "Full Scan" workflow runs all tools in order:
  1. Domain security (DNS, email, RDAP)
  2. Subfinder (passive subdomain enumeration)
  3. DNSx (DNS resolution, public IP filtering)
  4. Naabu (port scanning)
  5. HTTPx (web probe, URL discovery)
  6. Nmap (NSE vulners on non-web ports)
  7. TLS checker (all open ports)
  8. SSH checker (SSH ports)
  9. Nuclei (web vulnerability scanning on URLs)
  10. Web checker (security headers, cookies, CORS, disclosure)

After tools complete: finalise session, delta detection, insights, alerts.
"""

import logging

from django.db import transaction, DatabaseError
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

    from apps.core.findings.models import Finding

    current_keys = {
        f"{f.source}:{f.check_type}:{f.title}"
        for f in Finding.objects.filter(session=session)
    }
    prev_keys = {
        f"{f.source}:{f.check_type}:{f.title}"
        for f in Finding.objects.filter(session=previous)
    }
    deltas = []
    for key in current_keys - prev_keys:
        deltas.append(ScanDelta(session=session, previous_session=previous,
                                change_type="new", change_category="finding",
                                item_identifier=key))
    for key in prev_keys - current_keys:
        deltas.append(ScanDelta(session=session, previous_session=previous,
                                change_type="removed", change_category="finding",
                                item_identifier=key))
    if deltas:
        ScanDelta.objects.bulk_create(deltas)


def _count_all_findings(session) -> int:
    try:
        from apps.core.findings.models import Finding
        return Finding.objects.filter(session=session).count()
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Post-scan finalisation
# ---------------------------------------------------------------------------

def _finalize_session(session):
    """Post-scan: count findings, mark completed, detect deltas, build insights, dispatch alerts."""
    session_id = session.id
    total = _count_all_findings(session)
    session.total_findings = total
    session.status = "completed"
    session.end_time = django_tz.now()
    session.save(update_fields=["total_findings", "status", "end_time"])
    logger.info(f"[scan:{session_id}] Completed — {total} findings")

    _detect_deltas(session)

    from apps.core.insights.builder import build_insights
    build_insights(session)

    _dispatch_alerts(session)


# ---------------------------------------------------------------------------
# Concurrency guard
# ---------------------------------------------------------------------------

def _is_scan_active(domain: str) -> bool:
    """Return True if a pending or running scan already exists for this domain."""
    return ScanSession.objects.filter(
        domain=domain, status__in=["pending", "running"]
    ).exists()


def create_scan_session(domain: str, triggered_by: str = "manual", workflow=None) -> "ScanSession | None":
    """
    Atomically create a scan session if no active scan exists for the domain.
    Returns the new ScanSession or None if a scan is already active.

    If no workflow is specified, the default workflow is auto-assigned so all
    scans run through the dynamic workflow runner.
    """
    if workflow is None:
        from apps.core.workflows.models import Workflow
        workflow = Workflow.objects.filter(is_default=True).first()

    try:
        with transaction.atomic():
            # NOTE: select_for_update(nowait=True) is a no-op on SQLite — Django silently
            # ignores it. Real duplicate-session protection comes from workers=1 in
            # Q_CLUSTER and the if-active check below, not from DB-level locking.
            active = (
                ScanSession.objects
                .select_for_update(nowait=True)
                .filter(domain=domain, status__in=["pending", "running"])
                .exists()
            )
            if active:
                return None
            return ScanSession.objects.create(
                domain=domain, scan_type="full", status="pending",
                triggered_by=triggered_by, workflow=workflow,
            )
    except DatabaseError:
        if _is_scan_active(domain):
            logger.info(f"[create_scan_session] Scan already active for {domain} (confirmed via fallback read)")
            return None
        logger.warning(f"[create_scan_session] Transient lock contention for {domain} — retrying once")
        try:
            with transaction.atomic():
                active = (
                    ScanSession.objects
                    .select_for_update(nowait=True)
                    .filter(domain=domain, status__in=["pending", "running"])
                    .exists()
                )
                if active:
                    return None
                return ScanSession.objects.create(
                    domain=domain, scan_type="full", status="pending",
                    triggered_by=triggered_by, workflow=workflow,
                )
        except DatabaseError:
            logger.error(f"[create_scan_session] Retry failed for {domain} — skipping scan")
            return None


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(session_id: int):
    """Execute a scan session via its attached workflow, then finalise."""
    session = ScanSession.objects.select_related("workflow").get(id=session_id)
    session.status = "running"
    session.save(update_fields=["status"])
    logger.info(f"[scan:{session_id}] Starting scan for {session.domain}")

    try:
        _run_via_workflow(session)
        session.refresh_from_db(fields=["status"])
        if session.status == "cancelled":
            logger.info(f"[scan:{session_id}] Scan was cancelled — skipping finalization")
            return
        _finalize_session(session)
    except Exception as exc:
        logger.error(f"[scan:{session_id}] Scan failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])


def _run_via_workflow(session):
    """Run scan using the session's Workflow definition."""
    from apps.core.workflows.models import WorkflowRun
    from apps.core.workflows.runner import run_workflow

    if not session.workflow_id:
        raise RuntimeError(
            f"Session {session.id} has no workflow assigned. "
            f"Ensure a default workflow exists (run migrations)."
        )

    run = WorkflowRun.objects.create(workflow=session.workflow, session=session)
    run_workflow(run.id)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def _dispatch_alerts(session):
    """Fire alerts if SLACK_WEBHOOK_URL is configured."""
    from django.conf import settings
    if not getattr(settings, "SLACK_WEBHOOK_URL", ""):
        return
    threshold = getattr(settings, "ALERT_SEVERITY_THRESHOLD", "high")
    try:
        from apps.core.notifications.dispatcher import dispatch_alerts
        dispatch_alerts(session.id, severity_threshold=threshold)
    except Exception as e:
        logger.error(f"[scan:{session.id}] Alert dispatch failed: {e}", exc_info=True)
