"""
Scan orchestration for OpenEASD.

Phases:
  1. Apex domain security (DNS, email, RDAP)
  2. Update session totals
  3. Delta detection
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

    # Domain finding deltas
    current_keys = {
        f"{f.check_type}:{f.title}" for f in session.domain_findings.all()
    }
    prev_keys = {
        f"{f.check_type}:{f.title}" for f in previous.domain_findings.all()
    }
    for key in current_keys - prev_keys:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="new", change_category="domain_finding",
                                 item_identifier=key)
    for key in prev_keys - current_keys:
        ScanDelta.objects.create(session=session, previous_session=previous,
                                 change_type="removed", change_category="domain_finding",
                                 item_identifier=key)


def _count_all_findings(session) -> int:
    try:
        return session.domain_findings.count()
    except Exception:
        return 0


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
        from apps.domain_security.scanner import run_domain_security
        run_domain_security(session)

        # Phase 2: Update session totals
        total = _count_all_findings(session)
        session.total_findings = total
        session.status = "completed"
        session.end_time = django_tz.now()
        session.save(update_fields=["total_findings", "status", "end_time"])
        logger.info(f"[scan:{session_id}] Completed with {total} total findings")

        # Phase 3: Delta detection
        logger.info(f"[scan:{session_id}] Phase 3: Delta detection")
        _detect_deltas(session)

        # Phase 4: Build insights
        logger.info(f"[scan:{session_id}] Phase 4: Building insights")
        from apps.insights.builder import build_insights
        build_insights(session)

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
            from apps.insights.builder import build_insights
            build_insights(session)

    except Exception as exc:
        logger.error(f"[scan:{session_id}] Workflow run failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])


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
        session = ScanSession.objects.create(domain=domain.name, scan_type="full")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[daily_scan] Launched scan for {domain.name} (session {session.id})")


def weekly_scan():
    from apps.domains.models import Domain

    active_domains = Domain.objects.filter(is_active=True)
    if not active_domains.exists():
        logger.info("[weekly_scan] No active domains found")
        return

    for domain in active_domains:
        session = ScanSession.objects.create(domain=domain.name, scan_type="full")
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[weekly_scan] Launched full scan for {domain.name} (session {session.id})")
