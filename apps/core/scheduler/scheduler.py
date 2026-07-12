"""Django-Q2 scheduling for OpenEASD — replaces APScheduler."""

import json
import logging

from django.utils import timezone as django_tz

logger = logging.getLogger(__name__)

from decouple import config as _config  # noqa: E402
# Must be >= Q_CLUSTER["timeout"] (4h / 14400s). The watchdog only cleans up the
# DB status of scans whose worker died without finalizing; it must not fire while
# a healthy scan is still legitimately running, or it flips a live scan to
# "partial" mid-run. Keep this at/above the worker hard-kill (240m).
SCAN_TIMEOUT_MINUTES = _config("SCAN_TIMEOUT_MINUTES", default=240, cast=int)

# A scan stuck in "pending" never started running — its enqueued Django-Q task was
# lost (e.g. the qcluster worker restarted between enqueue and pickup), so it sits
# in "pending" forever. Because the per-domain concurrency guard counts pending
# scans as active, one orphaned pending scan blocks every new scan for that domain
# indefinitely (observed in prod: a scan sat pending ~6h and blocked the domain).
# Reap these far sooner than running scans: a pending scan has no work in flight,
# so it doesn't need the 4h running budget — it only needs long enough to be sure
# a healthy worker would already have picked it up (queue behind other scans is
# possible, so keep a generous margin over normal wait). Tunable for deployments
# that legitimately queue scans for long stretches behind long-running ones.
SCAN_PENDING_TIMEOUT_MINUTES = _config("SCAN_PENDING_TIMEOUT_MINUTES", default=60, cast=int)


# ---------------------------------------------------------------------------
# Core schedule setup (called once on qcluster startup)
# ---------------------------------------------------------------------------

def setup_core_schedules():
    """Register/update the fixed system schedules in Django-Q2.

    System-hygiene schedules (stuck-scan watchdog, token purge) always run.
    The unattended-scan schedules (daily scan + per-domain monitoring) are
    registered only when SCHEDULED_SCANS_ENABLED is True; when False they are
    actively removed, so flipping the flag on a running deployment takes effect
    on the next startup even if the schedules were created by an earlier boot.
    """
    from django.conf import settings
    from django_q.models import Schedule

    # --- System-hygiene schedules (always on) ---
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

    # --- Unattended-scan schedules (gated by the master switch) ---
    if not settings.SCHEDULED_SCANS_ENABLED:
        removed = Schedule.objects.filter(name="daily_scan").delete()[0]
        removed += Schedule.objects.filter(name__startswith="monitor_").delete()[0]
        logger.info(
            "[scheduler] SCHEDULED_SCANS_ENABLED=False — manual-only mode; "
            f"removed {removed} auto-scan schedule(s). Hygiene schedules registered."
        )
        return

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
    # Only monitor domains that are both active and authorized — an unauthorized
    # domain must never be scanned unattended, mirroring the daily_scan gate.
    monitored = Domain.objects.filter(
        is_active=True,
        monitoring_interval_hours__isnull=False,
        authorization__isnull=False,
    )
    for domain in monitored:
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

def _is_authorized(domain: str) -> bool:
    """True only if the domain has a DomainAuthorization record on file.

    The consent gate for every unattended scan entry point. Manual/API scans
    enforce this separately at the view layer; this guards the scheduler paths
    so a lingering schedule can never scan a domain whose authorization was
    revoked after the schedule was created.
    """
    from apps.core.domains.models import Domain

    return Domain.objects.filter(name=domain, authorization__isnull=False).exists()


def run_monitoring_scan(domain: str):
    """Run a monitoring scan for a single domain."""
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    if not _is_authorized(domain):
        logger.warning(f"[monitoring] Skipping {domain} — no domain authorization on file")
        return

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
    """Run a scan for every active, authorized domain.

    Gated on DomainAuthorization: a domain with no authorization record is never
    scanned unattended, even when active. This mirrors the manual entry-point
    gate (scan-start API + UI dropdown) so the scheduler can't bypass consent.
    """
    from apps.core.domains.models import Domain
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    active_domains = Domain.objects.filter(is_active=True, authorization__isnull=False)
    if not active_domains.exists():
        logger.info("[daily_scan] No active authorized domains found")
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
    Reap scans wedged past their timeout, using a separate cutoff per status.

    - `running` scans are reaped after SCAN_TIMEOUT_MINUTES (must stay >= the
      worker hard-kill so a healthy long scan is never flipped mid-run).
    - `pending` scans are reaped after SCAN_PENDING_TIMEOUT_MINUTES, which is far
      shorter: a pending scan never started, so it doesn't need the running budget.
      This is what stops an orphaned pending scan (lost Django-Q task after a worker
      restart) from blocking a domain for hours via the pending-counting guard.

    A scan that had at least one step complete before the timeout is reaped as
    `partial` (its findings are kept and shown). A scan with no completed steps
    (all pending scans, since they never created a WorkflowRun) is reaped as
    `failed`. Any step still in-flight at reap time is marked `failed` with a
    reason in `error` so the UI shows what was killed.
    """
    from django.db.models import Q

    from apps.core.scans.models import ScanSession

    now = django_tz.now()
    running_cutoff = now - django_tz.timedelta(minutes=SCAN_TIMEOUT_MINUTES)
    pending_cutoff = now - django_tz.timedelta(minutes=SCAN_PENDING_TIMEOUT_MINUTES)
    stuck_qs = ScanSession.objects.filter(
        Q(status="running", start_time__lt=running_cutoff)
        | Q(status="pending", start_time__lt=pending_cutoff)
    ).select_related("workflow_run")

    reap_msg = "reaped by watchdog after timeout"
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
