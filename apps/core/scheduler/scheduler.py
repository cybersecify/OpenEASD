"""APScheduler setup and scheduled scan functions for OpenEASD."""

import logging

from django.utils import timezone as django_tz

logger = logging.getLogger(__name__)

_scheduler = None

# A scan running longer than this is considered stuck and will be marked failed.
# Must exceed Q_CLUSTER timeout (3600s = 60 min) so legitimate long scans aren't reaped.
# Override with SCAN_TIMEOUT_MINUTES env var if needed.
from decouple import config as _config  # noqa: E402
SCAN_TIMEOUT_MINUTES = _config("SCAN_TIMEOUT_MINUTES", default=90, cast=int)


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

    # Purge expired blacklisted JWT refresh tokens (runs daily at 03:00)
    scheduler.add_job(
        purge_expired_blacklisted_tokens,
        trigger=CronTrigger(hour=3, minute=0),
        id="purge_blacklisted_tokens",
        name="Purge expired blacklisted JWT tokens",
        jobstore="default",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    scheduler.start()
    logger.info(
        f"Scheduler started — daily scan at {settings.SCAN_DAILY_HOUR:02d}:{settings.SCAN_DAILY_MINUTE:02d} IST"
    )
    # Re-register per-domain monitoring jobs from DB state on every startup.
    # Covers fresh deployments with pre-seeded databases and post-upgrade restarts.
    sync_domain_monitoring_jobs()


# ---------------------------------------------------------------------------
# Scheduled scan functions
# ---------------------------------------------------------------------------

def run_monitoring_scan(domain: str):
    """Run a monitoring scan for a single domain (called by per-domain APScheduler jobs)."""
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    session = create_scan_session(domain, triggered_by="monitoring")
    if session is None:
        logger.info(f"[monitoring] Skipping {domain} — scan already active")
        return
    run_scan_task(session.id)
    logger.info(f"[monitoring] Launched monitoring scan for {domain} (session {session.id})")


def sync_domain_monitoring_jobs():
    """Create/remove per-domain APScheduler jobs based on Domain.monitoring_interval_hours."""
    from apps.core.domains.models import Domain

    scheduler = get_scheduler()
    existing_ids = {j.id for j in scheduler.get_jobs() if j.id.startswith("monitor_")}
    wanted_ids = set()

    for domain in Domain.objects.filter(is_active=True, monitoring_interval_hours__isnull=False):
        job_id = f"monitor_{domain.name}"
        wanted_ids.add(job_id)
        interval = domain.monitoring_interval_hours

        if interval < 168:
            from apscheduler.triggers.interval import IntervalTrigger
            trigger = IntervalTrigger(hours=interval)
        else:
            from apscheduler.triggers.cron import CronTrigger
            trigger = CronTrigger(day_of_week="mon", hour=2, minute=0)

        scheduler.add_job(
            run_monitoring_scan,
            args=[domain.name],
            trigger=trigger,
            id=job_id,
            name=f"Monitoring: {domain.name} (every {interval}h)",
            jobstore="default",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        logger.info(f"[monitoring] Registered job {job_id} every {interval}h")

    for stale_id in existing_ids - wanted_ids:
        try:
            scheduler.remove_job(stale_id, jobstore="default")
            logger.info(f"[monitoring] Removed stale job {stale_id}")
        except Exception:
            pass


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


# ---------------------------------------------------------------------------
# JWT token cleanup
# ---------------------------------------------------------------------------

def purge_expired_blacklisted_tokens():
    """Delete expired OutstandingToken rows (and their BlacklistedToken entries) to keep the table small."""
    from ninja_jwt.token_blacklist.models import OutstandingToken

    cutoff = django_tz.now()
    deleted, _ = OutstandingToken.objects.filter(expires_at__lt=cutoff).delete()
    if deleted:
        logger.info(f"[token_purge] Deleted {deleted} expired outstanding token(s)")
    return deleted
