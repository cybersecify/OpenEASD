"""Django-Q2 scheduling for OpenEASD — replaces APScheduler."""

import json
import logging

from django.utils import timezone as django_tz

logger = logging.getLogger(__name__)

from decouple import config as _config  # noqa: E402
# Must be >= Q_CLUSTER["timeout"] (3h / 10800s). The watchdog only cleans up the
# DB status of scans whose worker died without finalizing; it must not fire while
# a healthy scan is still legitimately running, or it flips a live scan to
# "partial" mid-run. Keep this at/above the worker hard-kill (180m).
SCAN_TIMEOUT_MINUTES = _config("SCAN_TIMEOUT_MINUTES", default=180, cast=int)


# ---------------------------------------------------------------------------
# Core schedule setup (called once on qcluster startup)
# ---------------------------------------------------------------------------

def setup_core_schedules():
    """Register/update the three fixed system schedules in Django-Q2."""
    from django.conf import settings
    from django_q.models import Schedule

    hour   = settings.SCAN_DAILY_HOUR
    minute = settings.SCAN_DAILY_MINUTE

    Schedule.objects.update_or_create(
        name="daily_scan",
        defaults={
            "func":          "apps.core.scheduler.scheduler.daily_scan",
            "schedule_type": Schedule.CRON,
            "cron":          f"{minute} {hour} * * *",
            "repeats":       -1,
        },
    )
    Schedule.objects.update_or_create(
        name="watchdog_reap_stuck_scans",
        defaults={
            "func":          "apps.core.scheduler.scheduler.reap_stuck_scans",
            "schedule_type": Schedule.MINUTES,
            "minutes":       15,
            "repeats":       -1,
        },
    )
    Schedule.objects.update_or_create(
        name="purge_blacklisted_tokens",
        defaults={
            "func":          "apps.core.scheduler.scheduler.purge_expired_blacklisted_tokens",
            "schedule_type": Schedule.CRON,
            "cron":          "0 3 * * *",
            "repeats":       -1,
        },
    )
    logger.info(
        f"[scheduler] Core schedules registered — daily scan at {hour:02d}:{minute:02d}"
    )
    sync_domain_monitoring_jobs()


# ---------------------------------------------------------------------------
# Per-domain monitoring job sync
# ---------------------------------------------------------------------------

def sync_domain_monitoring_jobs():
    """Sync Django-Q2 Schedule entries with Domain.monitoring_interval_hours."""
    from apps.core.domains.models import Domain
    from django_q.models import Schedule

    wanted_names = set()
    for domain in Domain.objects.filter(is_active=True, monitoring_interval_hours__isnull=False):
        name     = f"monitor_{domain.name}"
        interval = domain.monitoring_interval_hours
        wanted_names.add(name)

        Schedule.objects.update_or_create(
            name=name,
            defaults={
                "func":          "apps.core.scheduler.scheduler.run_monitoring_scan",
                "args":          json.dumps([domain.name]),
                "schedule_type": Schedule.MINUTES,
                "minutes":       interval * 60,
                "repeats":       -1,
            },
        )
        logger.info(f"[monitoring] Registered schedule {name} every {interval}h")

    # Remove schedules for domains that were deleted or deactivated
    removed = Schedule.objects.filter(
        name__startswith="monitor_"
    ).exclude(name__in=wanted_names).delete()
    if removed[0]:
        logger.info(f"[monitoring] Removed {removed[0]} stale monitoring schedule(s)")


# ---------------------------------------------------------------------------
# Callable functions (must be importable module-level paths for Django-Q2)
# ---------------------------------------------------------------------------

def run_monitoring_scan(domain: str):
    """Run a monitoring scan for a single domain."""
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    session = create_scan_session(domain, triggered_by="monitoring")
    if session is None:
        logger.info(f"[monitoring] Skipping {domain} — scan already active")
        return
    run_scan_task(session.id)
    logger.info(f"[monitoring] Launched monitoring scan for {domain} (session {session.id})")


def run_scheduled_scan(domain: str, triggered_by: str = "scheduled"):
    """Top-level callable for Django-Q2 one-time and recurring scan jobs."""
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    session = create_scan_session(domain, triggered_by=triggered_by)
    if session is None:
        logger.info(f"[scheduled_scan] Skipping {domain} — scan already active")
        return
    run_scan_task(session.id)
    logger.info(f"[scheduled_scan] Launched scan for {domain} (session {session.id})")


def daily_scan():
    """Run a scan for every active domain."""
    from apps.core.domains.models import Domain
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    active_domains = Domain.objects.filter(is_active=True)
    if not active_domains.exists():
        logger.info("[daily_scan] No active domains found")
        return

    for domain in active_domains:
        session = create_scan_session(domain.name)
        if session is None:
            logger.info(f"[daily_scan] Skipping {domain.name} — scan already active")
            continue
        run_scan_task(session.id)
        logger.info(f"[daily_scan] Launched scan for {domain.name} (session {session.id})")


# ---------------------------------------------------------------------------
# Stuck scan watchdog
# ---------------------------------------------------------------------------

def reap_stuck_scans():
    """
    Reap scans that have been running/pending beyond SCAN_TIMEOUT_MINUTES.

    A scan that had at least one step complete before the timeout is reaped as
    `partial` (its findings are kept and shown). A scan with no completed steps
    is reaped as `failed`. Any step still in-flight at reap time is marked
    `failed` with a reason in `error` so the UI shows what was killed.
    """
    from apps.core.scans.models import ScanSession

    now = django_tz.now()
    cutoff = now - django_tz.timedelta(minutes=SCAN_TIMEOUT_MINUTES)
    stuck_qs = ScanSession.objects.filter(
        status__in=["pending", "running"],
        start_time__lt=cutoff,
    ).select_related("workflow_run")

    reap_msg = f"reaped by watchdog after {SCAN_TIMEOUT_MINUTES}m"
    partial_count = 0
    failed_count = 0

    for session in stuck_qs:
        run = getattr(session, "workflow_run", None)
        completed_step = False
        if run is not None:
            in_flight = run.step_results.filter(status__in=["pending", "running"])
            in_flight.update(status="failed", finished_at=now, error=reap_msg)
            completed_step = run.step_results.filter(status="completed").exists()
            run.status = "partial" if completed_step else "failed"
            run.finished_at = now
            run.save(update_fields=["status", "finished_at"])

        new_status = "partial" if completed_step else "failed"
        session.status = new_status
        session.end_time = now
        # _finalize_session never ran (the wedged step held the worker), so
        # total_findings is still 0 even though completed steps wrote Findings.
        # Recompute it here so reaped scans show their real count, not 0.
        from apps.core.scans.pipeline import _count_all_findings
        session.total_findings = _count_all_findings(session)
        session.save(update_fields=["status", "end_time", "total_findings"])

        if new_status == "partial":
            partial_count += 1
        else:
            failed_count += 1

    total = partial_count + failed_count
    if total:
        logger.warning(
            f"[watchdog] Reaped {total} stuck scan(s) — "
            f"{partial_count} as partial (kept findings), {failed_count} as failed"
        )
    return total


# ---------------------------------------------------------------------------
# JWT token cleanup
# ---------------------------------------------------------------------------

def purge_expired_blacklisted_tokens():
    """Delete expired OutstandingToken rows to keep the table small."""
    from ninja_jwt.token_blacklist.models import OutstandingToken

    cutoff = django_tz.now()
    deleted, _ = OutstandingToken.objects.filter(expires_at__lt=cutoff).delete()
    if deleted:
        logger.info(f"[token_purge] Deleted {deleted} expired outstanding token(s)")
    return deleted
