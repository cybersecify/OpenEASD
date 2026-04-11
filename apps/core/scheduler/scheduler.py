"""APScheduler setup for OpenEASD daily scan automation."""

import logging

logger = logging.getLogger(__name__)

_scheduler = None


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
    from apps.core.scans.pipeline import daily_scan, reap_stuck_scans

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
