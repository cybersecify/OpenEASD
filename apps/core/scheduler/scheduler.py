"""APScheduler setup and scheduled scan functions for OpenEASD."""

import logging

from django.utils import timezone as django_tz

logger = logging.getLogger(__name__)

_scheduler = None

# A scan running longer than this is considered stuck and will be marked failed.
SCAN_TIMEOUT_MINUTES = 30


def get_scheduler():
    """Return the shared scheduler instance (created lazily)."""
    global _scheduler
    if _scheduler is None:
        from apscheduler.schedulers.background import BackgroundScheduler
        from django.conf import settings
        _scheduler = BackgroundScheduler(timezone=settings.TIME_ZONE)
    return _scheduler


def start_scheduler():
    from apscheduler.triggers.cron import CronTrigger
    from django.conf import settings
    from django_apscheduler.jobstores import DjangoJobStore

    scheduler = get_scheduler()
    scheduler.add_jobstore(DjangoJobStore(), "default")

    scheduler.add_job(
        daily_scan,
        trigger=CronTrigger(
            hour=settings.SCAN_DAILY_HOUR,
            minute=settings.SCAN_DAILY_MINUTE,
        ),
        id="daily_scan",
        name="Daily domain vulnerability scan",
        jobstore="default",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # Watchdog: reap scans stuck in pending/running beyond SCAN_TIMEOUT_MINUTES
    scheduler.add_job(
        reap_stuck_scans,
        trigger=CronTrigger(minute="*/15"),
        id="watchdog_reap_stuck_scans",
        name="Reap stuck scans",
        jobstore="default",
        replace_existing=True,
        misfire_grace_time=300,
    )

    scheduler.start()
    logger.info(
        f"Scheduler started — daily scan at {settings.SCAN_DAILY_HOUR:02d}:{settings.SCAN_DAILY_MINUTE:02d} IST"
    )


# ---------------------------------------------------------------------------
# Scheduled scan functions
# ---------------------------------------------------------------------------

def run_scheduled_scan(domain: str, triggered_by: str = "scheduled"):
    """
    Top-level callable for APScheduler jobs (one-time and recurring).
    Must be a module-level function so APScheduler can serialize it by reference.
    """
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    session = create_scan_session(domain, triggered_by=triggered_by)
    if session is None:
        logger.info(f"[scheduled_scan] Skipping {domain} — scan already active")
        return
    run_scan_task(session.id)
    logger.info(f"[scheduled_scan] Launched scan for {domain} (session {session.id})")


def daily_scan():
    """Run a scan for every active domain. Called by APScheduler daily."""
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


def weekly_scan():
    """Run a full scan for every active domain. Called by APScheduler weekly."""
    from apps.core.domains.models import Domain
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    active_domains = Domain.objects.filter(is_active=True)
    if not active_domains.exists():
        logger.info("[weekly_scan] No active domains found")
        return

    for domain in active_domains:
        session = create_scan_session(domain.name)
        if session is None:
            logger.info(f"[weekly_scan] Skipping {domain.name} — scan already active")
            continue
        run_scan_task(session.id)
        logger.info(f"[weekly_scan] Launched full scan for {domain.name} (session {session.id})")


# ---------------------------------------------------------------------------
# Stuck scan watchdog
# ---------------------------------------------------------------------------

def reap_stuck_scans():
    """
    Mark scans that have been running/pending beyond SCAN_TIMEOUT_MINUTES as failed.
    Called by the scheduler; safe to call multiple times concurrently.
    """
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
