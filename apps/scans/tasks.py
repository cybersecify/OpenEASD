"""
Scan orchestration for OpenEASD.

Phases:
  1. Apex domain security (DNS, email, RDAP)
  2. Update session totals + mark completed
  3. Delta detection
  4. Build insights
  5. Dispatch alerts
"""

import logging
import threading

from django.utils import timezone as django_tz

from .models import ScanSession, ScanDelta

logger = logging.getLogger(__name__)

# A scan running longer than this is considered stuck and will be marked failed.
SCAN_TIMEOUT_MINUTES = 30


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

    current_keys = {
        f"{f.check_type}:{f.title}" for f in session.domain_findings.all()
    }
    prev_keys = {
        f"{f.check_type}:{f.title}" for f in previous.domain_findings.all()
    }
    deltas = []
    for key in current_keys - prev_keys:
        deltas.append(ScanDelta(session=session, previous_session=previous,
                                change_type="new", change_category="domain_finding",
                                item_identifier=key))
    for key in prev_keys - current_keys:
        deltas.append(ScanDelta(session=session, previous_session=previous,
                                change_type="removed", change_category="domain_finding",
                                item_identifier=key))
    if deltas:
        ScanDelta.objects.bulk_create(deltas)


def _count_all_findings(session) -> int:
    try:
        return session.domain_findings.count()
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Concurrency guard
# ---------------------------------------------------------------------------

def _is_scan_active(domain: str) -> bool:
    """Return True if a pending or running scan already exists for this domain."""
    return ScanSession.objects.filter(
        domain=domain, status__in=["pending", "running"]
    ).exists()


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(session_id: int):
    session = ScanSession.objects.select_related("workflow").get(id=session_id)
    domain = session.domain

    session.status = "running"
    session.save(update_fields=["status"])
    logger.info(f"[scan:{session_id}] Starting scan for {domain}")

    # If a workflow is attached, delegate to workflow runner
    if session.workflow_id:
        _run_via_workflow(session)
        return

    try:
        # Phase 1: Apex domain security
        logger.info(f"[scan:{session_id}] Phase 1: domain security")
        from apps.domain_security.scanner import run_domain_security
        run_domain_security(session)

        # Phase 2: Finalise session
        total = _count_all_findings(session)
        session.total_findings = total
        session.status = "completed"
        session.end_time = django_tz.now()
        session.save(update_fields=["total_findings", "status", "end_time"])
        logger.info(f"[scan:{session_id}] Completed — {total} findings")

        # Phase 3: Delta detection
        _detect_deltas(session)

        # Phase 4: Build insights
        from apps.insights.builder import build_insights
        build_insights(session)

        # Phase 5: Alerts
        _dispatch_alerts(session)

    except Exception as exc:
        logger.error(f"[scan:{session_id}] Scan failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])


def _run_via_workflow(session):
    """Run scan using a Workflow definition, then finalise the session."""
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
            from apps.insights.builder import build_insights
            build_insights(session)
            _dispatch_alerts(session)

    except Exception as exc:
        logger.error(f"[scan:{session_id}] Workflow run failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])


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
        from apps.alerts.dispatcher import dispatch_alerts
        dispatch_alerts(session.id, severity_threshold=threshold)
    except Exception as e:
        logger.warning(f"[scan:{session.id}] Alert dispatch failed: {e}")


# ---------------------------------------------------------------------------
# Stuck scan watchdog
# ---------------------------------------------------------------------------

def reap_stuck_scans():
    """
    Mark scans that have been running/pending beyond SCAN_TIMEOUT_MINUTES as failed.
    Called by the scheduler; safe to call multiple times concurrently.
    """
    cutoff = django_tz.now() - django_tz.timedelta(minutes=SCAN_TIMEOUT_MINUTES)
    stuck = ScanSession.objects.filter(
        status__in=["pending", "running"],
        start_time__lt=cutoff,
    )
    count = stuck.count()
    if count:
        stuck.update(status="failed", end_time=django_tz.now())
        logger.warning(f"[watchdog] Reaped {count} stuck scan(s)")
    return count


# ---------------------------------------------------------------------------
# Scheduled scan functions
# ---------------------------------------------------------------------------

def daily_scan():
    from apps.domains.models import Domain

    active_domains = Domain.objects.filter(is_active=True)
    if not active_domains.exists():
        logger.info("[daily_scan] No active domains found")
        return

    for domain in active_domains:
        if _is_scan_active(domain.name):
            logger.info(f"[daily_scan] Skipping {domain.name} — scan already active")
            continue
        session = ScanSession.objects.create(domain=domain.name, scan_type="full", status="pending")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[daily_scan] Launched scan for {domain.name} (session {session.id})")


def weekly_scan():
    from apps.domains.models import Domain

    active_domains = Domain.objects.filter(is_active=True)
    if not active_domains.exists():
        logger.info("[weekly_scan] No active domains found")
        return

    for domain in active_domains:
        if _is_scan_active(domain.name):
            logger.info(f"[weekly_scan] Skipping {domain.name} — scan already active")
            continue
        session = ScanSession.objects.create(domain=domain.name, scan_type="full", status="pending")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[weekly_scan] Launched full scan for {domain.name} (session {session.id})")
