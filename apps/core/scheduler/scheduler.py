"""Django-Q2 scheduling for OpenEASD — replaces APScheduler."""

import json
import logging

from django.utils import timezone as django_tz

logger = logging.getLogger(__name__)

from decouple import config as _config  # noqa: E402
SCAN_TIMEOUT_MINUTES = _config("SCAN_TIMEOUT_MINUTES", default=90, cast=int)


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
    """Mark scans stuck in pending/running beyond SCAN_TIMEOUT_MINUTES as failed."""
    from apps.core.scans.models import ScanSession

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
