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

from django.db import transaction, DatabaseError
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

    from apps.core.findings.models import Finding

    current_keys = {
        f"{f.check_type}:{f.title}"
        for f in Finding.objects.filter(session=session, source="domain_security")
    }
    prev_keys = {
        f"{f.check_type}:{f.title}"
        for f in Finding.objects.filter(session=previous, source="domain_security")
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
        from apps.core.findings.models import Finding
        return Finding.objects.filter(session=session).count()
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


def create_scan_session(domain: str, triggered_by: str = "manual") -> "ScanSession | None":
    """
    Atomically create a scan session if no active scan exists for the domain.
    Returns the new ScanSession or None if a scan is already active.
    Uses SELECT FOR UPDATE to prevent race conditions between concurrent requests.
    """
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
            return ScanSession.objects.create(domain=domain, scan_type="full", status="pending", triggered_by=triggered_by)
    except DatabaseError:
        # SQLite write lock was held by another transaction (transient contention).
        # Fall back to a plain read to check if a scan is genuinely active.
        if _is_scan_active(domain):
            logger.info(f"[create_scan_session] Scan already active for {domain} (confirmed via fallback read)")
            return None
        logger.warning(f"[create_scan_session] Transient lock contention for {domain} — retrying once")
        # Retry once without nowait; if it fails again we give up.
        try:
            with transaction.atomic():
                active = (
                    ScanSession.objects
                    .select_for_update()
                    .filter(domain=domain, status__in=["pending", "running"])
                    .exists()
                )
                if active:
                    return None
                return ScanSession.objects.create(domain=domain, scan_type="full", status="pending", triggered_by=triggered_by)
        except DatabaseError:
            logger.error(f"[create_scan_session] Retry failed for {domain} — skipping scan")
            return None


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

        # Phase 2: Subdomain discovery
        logger.info(f"[scan:{session_id}] Phase 2: subdomain discovery")
        try:
            from apps.subfinder.scanner import run_subfinder
            subdomains = run_subfinder(session)
            logger.info(f"[scan:{session_id}] Discovered {len(subdomains)} subdomains")
        except Exception as e:
            logger.error(f"[scan:{session_id}] Subfinder failed: {e}", exc_info=True)

        # Phase 3: DNS resolution + public IP filtering
        logger.info(f"[scan:{session_id}] Phase 3: dnsx resolution")
        try:
            from apps.dnsx.scanner import run_dnsx
            active = run_dnsx(session)
            logger.info(f"[scan:{session_id}] Active subdomains: {len(active)}")
        except Exception as e:
            logger.error(f"[scan:{session_id}] dnsx failed: {e}", exc_info=True)

        # Phase 4: Port scan (top 100 TCP) on public IPs
        logger.info(f"[scan:{session_id}] Phase 4: naabu port scan")
        try:
            from apps.naabu.scanner import run_naabu
            ports = run_naabu(session)
            logger.info(f"[scan:{session_id}] Open ports: {len(ports)}")
        except Exception as e:
            logger.error(f"[scan:{session_id}] naabu failed: {e}", exc_info=True)

        # Phase 5: HTTPx web/non-web classification
        logger.info(f"[scan:{session_id}] Phase 5: httpx web probe")
        try:
            from apps.httpx.scanner import run_httpx
            urls = run_httpx(session)
            logger.info(f"[scan:{session_id}] Web URLs: {len(urls)}")
        except Exception as e:
            logger.error(f"[scan:{session_id}] httpx failed: {e}", exc_info=True)

        # Phase 6: Nmap NSE vulners on non-web ports (Ports without URL records)
        logger.info(f"[scan:{session_id}] Phase 6: nmap NSE vulners")
        try:
            from apps.nmap.scanner import run_nmap
            nmap_findings = run_nmap(session)
            logger.info(f"[scan:{session_id}] Nmap CVE findings: {len(nmap_findings)}")
        except Exception as e:
            logger.error(f"[scan:{session_id}] nmap failed: {e}", exc_info=True)

        # Phase 7: Finalise session
        total = _count_all_findings(session)
        session.total_findings = total
        session.status = "completed"
        session.end_time = django_tz.now()
        session.save(update_fields=["total_findings", "status", "end_time"])
        logger.info(f"[scan:{session_id}] Completed — {total} findings")

        # Phase 3: Delta detection
        _detect_deltas(session)

        # Phase 4: Build insights
        from apps.core.insights.builder import build_insights
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
    from apps.core.workflows.models import WorkflowRun
    from apps.core.workflows.runner import run_workflow

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
            from apps.core.insights.builder import build_insights
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
        from apps.core.notifications.dispatcher import dispatch_alerts
        dispatch_alerts(session.id, severity_threshold=threshold)
    except Exception as e:
        logger.error(f"[scan:{session.id}] Alert dispatch failed: {e}", exc_info=True)


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

def run_scheduled_scan(domain: str, triggered_by: str = "scheduled"):
    """
    Top-level callable for APScheduler jobs (one-time and recurring).
    Must be a module-level function so APScheduler can serialize it by reference.
    """
    session = create_scan_session(domain, triggered_by=triggered_by)
    if session is None:
        logger.info(f"[scheduled_scan] Skipping {domain} — scan already active")
        return
    threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
    logger.info(f"[scheduled_scan] Launched scan for {domain} (session {session.id})")


def daily_scan():
    from apps.core.domains.models import Domain

    active_domains = Domain.objects.filter(is_active=True)
    if not active_domains.exists():
        logger.info("[daily_scan] No active domains found")
        return

    for domain in active_domains:
        session = create_scan_session(domain.name)
        if session is None:
            logger.info(f"[daily_scan] Skipping {domain.name} — scan already active")
            continue
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[daily_scan] Launched scan for {domain.name} (session {session.id})")


def weekly_scan():
    from apps.core.domains.models import Domain

    active_domains = Domain.objects.filter(is_active=True)
    if not active_domains.exists():
        logger.info("[weekly_scan] No active domains found")
        return

    for domain in active_domains:
        session = create_scan_session(domain.name)
        if session is None:
            logger.info(f"[weekly_scan] Skipping {domain.name} — scan already active")
            continue
        threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
        logger.info(f"[weekly_scan] Launched full scan for {domain.name} (session {session.id})")
