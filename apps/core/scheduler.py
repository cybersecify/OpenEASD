"""APScheduler setup for OpenEASD daily scan automation."""

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from django.conf import settings
from django_apscheduler.jobstores import DjangoJobStore

logger = logging.getLogger(__name__)

# Module-level singleton — views and tasks add jobs to this instance.
scheduler = BackgroundScheduler(timezone="UTC")


def get_scheduler() -> BackgroundScheduler:
    """Return the shared scheduler instance."""
    return scheduler


def start_scheduler():
    from apps.scans.tasks import daily_scan, reap_stuck_scans

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
        f"Scheduler started — daily scan at {settings.SCAN_DAILY_HOUR:02d}:{settings.SCAN_DAILY_MINUTE:02d} UTC"
    )
