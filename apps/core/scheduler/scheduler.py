"""Scan scheduling callables for OpenEASD.

On the `local` branch the cron layer is DBOS @scheduled workflows
(apps/core/durable/workflows.py); the functions here are the plain callables
those workflows invoke (daily_scan, run_due_monitoring_scans, reap_stuck_scans,
purge_expired_blacklisted_tokens). setup_core_schedules / sync_domain_monitoring_jobs
are retained as no-ops for legacy callers.
"""

import logging

from django.utils import timezone as django_tz

logger = logging.getLogger(__name__)

from decouple import config as _config  # noqa: E402
# Must be >= Q_CLUSTER["timeout"] (4h / 14400s). The watchdog only cleans up the
# DB status of scans whose worker died without finalizing; it must not fire while
# a healthy scan is still legitimately running, or it flips a live scan to
# "partial" mid-run. Keep this at/above the worker hard-kill (240m).
SCAN_TIMEOUT_MINUTES = _config("SCAN_TIMEOUT_MINUTES", default=1440, cast=int)  # 24h; >= Q_TASK_TIMEOUT

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
    """No-op on the DBOS branch.

    The unattended-scanning backbone (daily scan, monitoring sweep, watchdog,
    token purge) is now a set of DBOS @scheduled workflows in
    apps/core/durable/workflows.py, registered when the dbos_worker imports
    that module — there is no Django-Q Schedule setup to perform. Kept as a
    callable so any legacy caller (and the scheduler AppConfig) stays valid.
    """
    logger.info("[scheduler] setup_core_schedules is a no-op — schedules are DBOS @scheduled workflows")


def sync_domain_monitoring_jobs():
    """No-op on the DBOS branch.

    Per-domain monitoring is no longer one Django-Q timer per domain; the DBOS
    `scheduled_monitoring_sweep` workflow computes due-ness from scan history
    every sweep (see run_due_monitoring_scans). Domain add/edit/delete therefore
    needs no schedule re-sync — this stays a callable so the domains API's
    existing calls remain valid without change."""
    return


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


def run_due_monitoring_scans():
    """DBOS monitoring sweep: enqueue a scan for every active, authorized,
    monitored domain whose last scan is older than its interval. Replaces the
    per-domain Django-Q schedules — the sweep computes due-ness from scan
    history instead of one timer per domain, so nothing needs re-syncing when a
    domain's interval changes."""
    from datetime import timedelta

    from apps.core.domains.models import Domain
    from apps.core.scans.models import ScanSession

    now = django_tz.now()
    monitored = Domain.objects.filter(
        is_active=True,
        monitoring_interval_hours__isnull=False,
        authorization__isnull=False,
    )
    for domain in monitored:
        last = (
            ScanSession.objects.filter(domain=domain.name)
            .exclude(scan_type="subscan")
            .order_by("-start_time")
            .values_list("start_time", flat=True)
            .first()
        )
        due = last is None or (now - last) >= timedelta(hours=domain.monitoring_interval_hours)
        if due:
            run_monitoring_scan(domain.name)


def run_scheduled_scan(domain: str, triggered_by: str = "scheduled"):
    """Top-level callable for Django-Q2 one-time and recurring scan jobs.

    Re-checks consent at run time, mirroring daily_scan/run_monitoring_scan.
    A user-created recurring/one-time schedule is authorization-checked only
    when created (scans/api.start_scan); without this gate it would keep
    scanning a domain whose authorization was later revoked, that was
    deactivated, or that was deleted (a deleted domain has no row, so the
    active+authorized filter skips it). Gated on both is_active and
    authorization to match the daily_scan guarantee.
    """
    from apps.core.domains.models import Domain
    from apps.core.scans.pipeline import create_scan_session
    from apps.core.scans.tasks import run_scan_task

    is_scannable = Domain.objects.filter(
        name=domain, is_active=True, authorization__isnull=False
    ).exists()
    if not is_scannable:
        logger.warning(f"[scheduled_scan] Skipping {domain} — not an active, authorized domain")
        return

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
