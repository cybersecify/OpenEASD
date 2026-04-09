"""APScheduler setup for OpenEASD daily scan automation."""

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from django.conf import settings
from django_apscheduler.jobstores import DjangoJobStore

logger = logging.getLogger(__name__)


def start_scheduler():
    from apps.scans.tasks import daily_scan

    scheduler = BackgroundScheduler(timezone="UTC")
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
        misfire_grace_time=3600,  # run within 1hr if server was down at scheduled time
    )

    scheduler.start()
    logger.info(
        f"Scheduler started — daily scan at {settings.SCAN_DAILY_HOUR:02d}:{settings.SCAN_DAILY_MINUTE:02d} UTC"
    )
