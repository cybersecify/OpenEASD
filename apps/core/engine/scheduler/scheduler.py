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
# Must be >= the worker's scan hard-kill (SCAN_TASK_TIMEOUT). The watchdog only
# cleans up the DB status of scans whose worker died without finalizing; it must
# not fire while a healthy scan is still legitimately running, or it flips a live
# scan to "partial" mid-run. Keep this at/above the worker hard-kill (240m).
SCAN_TIMEOUT_MINUTES = _config("SCAN_TIMEOUT_MINUTES", default=1440, cast=int)  # 24h; >= SCAN_TASK_TIMEOUT

# A scan stuck in "pending" never started running — its enqueued workflow never
# got picked up (e.g. the worker was down between enqueue and pickup), so it sits
# in "pending" forever. Because the per-domain concurrency guard counts pending
# scans as active, one orphaned pending scan blocks every new scan for that domain
# indefinitely (observed in prod: a scan sat pending ~6h and blocked the domain).
# Reap these far sooner than running scans: a pending scan has no work in flight,
# so it doesn't need the 4h running budget — it only needs long enough to be sure
# a healthy worker would already have picked it up (queue behind other scans is
# possible, so keep a generous margin over normal wait). Tunable for deployments
# that legitimately queue scans for long stretches behind long-running ones.
SCAN_PENDING_TIMEOUT_MINUTES = _config("SCAN_PENDING_TIMEOUT_MINUTES", default=60, cast=int)

# H10 — no-progress watchdog. A running scan that has not completed a step (no
# heartbeat on ScanSession.last_progress_at) for this many minutes is treated as
# wedged and reaped, freeing its scarce concurrency slot in minutes rather than
# waiting out the 24h hard cap (SCAN_TIMEOUT_MINUTES). Must stay COMFORTABLY above
# the longest single-tool runtime (nuclei/amass can run tens of minutes and the
# heartbeat only ticks between steps) so a slow-but-alive scan is never killed.
SCAN_NO_PROGRESS_MINUTES = _config("SCAN_NO_PROGRESS_MINUTES", default=60, cast=int)


# ---------------------------------------------------------------------------
# Core schedule setup (legacy no-op — schedules are DBOS @scheduled workflows)
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
# Callable functions (invoked by the DBOS @scheduled sweeps in apps/core/durable)
# ---------------------------------------------------------------------------

def _is_authorized(domain: str) -> bool:
    """True only if the domain has a DomainAuthorization record on file.

    The consent gate for every unattended scan entry point. Manual/API scans
    enforce this separately at the view layer; this guards the scheduler paths
    so a lingering schedule can never scan a domain whose authorization was
    revoked after the schedule was created.
    """
    from apps.core.data.domains.models import Domain

    return Domain.objects.filter(name=domain, authorization__isnull=False).exists()


def run_monitoring_scan(domain: str):
    """Run a monitoring scan for a single domain."""
    from apps.core.engine.scans.pipeline import create_scan_session
    from apps.core.engine.scans.tasks import run_scan_task

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

    from apps.core.data.domains.models import Domain
    from apps.core.engine.scans.models import ScanSession

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


def run_due_user_scans():
    """DBOS sweep for user-created one-time/recurring schedules (ScheduledScan
    rows). Fires each due schedule via run_scheduled_scan; advances recurring
    schedules to their next cron time and deletes one-time schedules after they
    fire. Replaces the Django-Q ONCE/CRON Schedule rows."""
    from croniter import croniter

    from apps.core.engine.scans.models import ScheduledScan

    now = django_tz.now()
    for sched in ScheduledScan.objects.filter(enabled=True, next_run__lte=now):
        triggered_by = "recurring" if sched.kind == "recurring" else "scheduled"
        run_scheduled_scan(sched.domain, triggered_by=triggered_by)
        if sched.kind == "recurring" and sched.cron:
            sched.next_run = croniter(sched.cron, now).get_next(type(now))
            sched.save(update_fields=["next_run"])
        else:
            sched.delete()  # one-time: fired once, gone


def run_scheduled_scan(domain: str, triggered_by: str = "scheduled"):
    """Top-level callable for one-time and recurring scan jobs (invoked by the DBOS user-schedule sweep).

    Re-checks consent at run time, mirroring daily_scan/run_monitoring_scan.
    A user-created recurring/one-time schedule is authorization-checked only
    when created (scans/api.start_scan); without this gate it would keep
    scanning a domain whose authorization was later revoked, that was
    deactivated, or that was deleted (a deleted domain has no row, so the
    active+authorized filter skips it). Gated on both is_active and
    authorization to match the daily_scan guarantee.
    """
    from apps.core.data.domains.models import Domain
    from apps.core.engine.scans.pipeline import create_scan_session
    from apps.core.engine.scans.tasks import run_scan_task

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
    from apps.core.data.domains.models import Domain
    from apps.core.engine.scans.pipeline import create_scan_session
    from apps.core.engine.scans.tasks import run_scan_task

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
      This is what stops an orphaned pending scan (the worker was down between
      enqueue and pickup) from blocking a domain for hours via the pending-counting guard.

    A scan that had at least one step complete before the timeout is reaped as
    `partial` (its findings are kept and shown). A scan with no completed steps
    (all pending scans, since they never created a WorkflowRun) is reaped as
    `failed`. Any step still in-flight at reap time is marked `failed` with a
    reason in `error` so the UI shows what was killed.
    """
    from django.db.models import Q

    from apps.core.engine.scans.models import ScanSession

    now = django_tz.now()
    running_cutoff = now - django_tz.timedelta(minutes=SCAN_TIMEOUT_MINUTES)
    pending_cutoff = now - django_tz.timedelta(minutes=SCAN_PENDING_TIMEOUT_MINUTES)
    no_progress_cutoff = now - django_tz.timedelta(minutes=SCAN_NO_PROGRESS_MINUTES)
    # A running scan is stuck if EITHER it has exceeded the 24h hard cap
    # (SCAN_TIMEOUT_MINUTES) OR it has made no progress for
    # SCAN_NO_PROGRESS_MINUTES (H10). The heartbeat (ScanSession.last_progress_at,
    # stamped on every step completion) is the liveness signal: a slow-but-alive
    # scan keeps it fresh and is NOT reaped; a wedged scan goes stale and is freed
    # in minutes instead of a day. NULL heartbeat (no step has finished yet) falls
    # back to start_time, so a scan that never completes a first step is still
    # reaped once it's stale. NO_PROGRESS must exceed the longest single-tool
    # runtime (heartbeat is per-step), hence a generous default.
    running_stuck = Q(status="running") & (
        Q(start_time__lt=running_cutoff)
        | Q(last_progress_at__lt=no_progress_cutoff)
        | Q(last_progress_at__isnull=True, start_time__lt=no_progress_cutoff)
    )
    stuck_qs = ScanSession.objects.filter(
        running_stuck | Q(status="pending", start_time__lt=pending_cutoff)
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
        from apps.core.engine.scans.pipeline import _count_all_findings
        save_fields = ["status", "end_time"]
        try:
            session.total_findings = _count_all_findings(session)
            save_fields.append("total_findings")
        except Exception:  # noqa: BLE001 — a count hiccup must not abort the sweep
            # Leave total_findings as-is (don't fake a 0); the scan is already
            # labeled partial/failed, so a stale count here isn't misread as clean.
            logger.warning(
                "[watchdog] could not recount findings for scan %s — leaving total_findings unchanged",
                session.id, exc_info=True,
            )
        session.save(update_fields=save_fields)

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
# Orphaned-workflow reaper (H8 — free jammed `scans`-queue concurrency slots)
# ---------------------------------------------------------------------------

# A ScanSession is "live" only while it is pending or running; any other status
# is terminal. A DBOS run_scan workflow that is still ENQUEUED/PENDING while its
# ScanSession is terminal (or gone) is a *phantom*: it occupies a scarce
# `scans`-queue concurrency slot but has no live work behind it. With
# concurrency=2, a couple of phantoms permanently jam the queue so no new scan
# dequeues (observed 2026-09-12: a worker rollout orphaned in-flight run_scan
# workflows pinned to the old app-version; their sessions were later reaped to
# `failed` by reap_stuck_scans, but the DBOS workflows stayed PENDING and held
# both slots). This reaper cancels those phantoms so the slots free.
#
# It only ever cancels a workflow whose session is NOT live, so it can never kill
# a legitimately in-flight scan — making it safe to run unattended from the
# watchdog cron (no app-version guessing, no rolling-deploy race). Pending/running
# version-orphans are first flipped to terminal by reap_stuck_scans (pending after
# SCAN_PENDING_TIMEOUT_MINUTES), after which this reaper clears their workflows.
_SCAN_ACTIVE_STATUSES = {"pending", "running"}


def reap_orphaned_scan_workflows(apply: bool = True):
    """Cancel ENQUEUED/PENDING `run_scan` DBOS workflows whose ScanSession is
    terminal or missing (phantoms holding a `scans`-queue concurrency slot).

    Returns a list of ``(workflow_id, deduplication_id, session_status)`` tuples
    that were (or, when ``apply=False``, would be) cancelled. Fail-graceful: any
    error is logged and an empty list returned — it runs inside the watchdog cron
    and must never abort the sweep.
    """
    try:
        from apps.core.engine.durable.client import get_client
        from apps.core.engine.durable.constants import QUEUE_NAME
        from apps.core.engine.scans.models import ScanSession

        client = get_client()
        workflows = client.list_workflows(
            name="run_scan",
            status=["ENQUEUED", "PENDING"],
            queue_name=QUEUE_NAME,
            load_input=False,
            load_output=False,
        )
    except Exception:  # noqa: BLE001 — never abort the watchdog sweep
        logger.warning("[orphan-reaper] could not list run_scan workflows", exc_info=True)
        return []

    reaped = []
    for wf in workflows:
        dedup = getattr(wf, "deduplication_id", None) or ""
        # enqueue_scan() always sets deduplication_id="scan-{session_id}".
        session_id = None
        if dedup.startswith("scan-"):
            try:
                session_id = int(dedup[len("scan-"):])
            except ValueError:
                session_id = None

        if session_id is None:
            # No resolvable session handle — leave it; we only reap workflows we
            # can prove are orphaned (don't guess about un-mappable ones).
            continue

        status = (
            ScanSession.objects.filter(id=session_id)
            .values_list("status", flat=True)
            .first()
        )
        session_is_live = status in _SCAN_ACTIVE_STATUSES
        if session_is_live:
            continue  # a pending/running session may still be legitimate work

        # status is None (session deleted) or terminal → phantom slot holder.
        reaped.append((wf.workflow_id, dedup, status or "missing"))
        if apply:
            try:
                client.cancel_workflow(wf.workflow_id)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "[orphan-reaper] failed to cancel workflow %s (%s)",
                    wf.workflow_id, dedup, exc_info=True,
                )

    if reaped:
        verb = "Cancelled" if apply else "Would cancel"
        logger.warning(
            "[orphan-reaper] %s %d phantom run_scan workflow(s) holding a queue slot: %s",
            verb, len(reaped), ", ".join(f"{d}({s})" for _, d, s in reaped),
        )
    return reaped


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


# ---------------------------------------------------------------------------
# Scan retention / pruning (H3 — bounded result store)
# ---------------------------------------------------------------------------

def prune_old_scans():
    """Delete old scan history to bound DB growth — OPT-IN (no-op unless
    SCAN_RETENTION_ENABLED). Per domain, keep the newest
    SCAN_RETENTION_KEEP_PER_DOMAIN scans AND any newer than
    SCAN_RETENTION_MAX_AGE_DAYS; delete the rest. Invariants:

    - The single newest scan per domain is ALWAYS kept (a domain never ends up
      with zero scans, even if its newest is older than MAX_AGE_DAYS).
    - pending/running scans are NEVER deleted (they may be in-flight); only
      terminal scans are deletion candidates.
    - Deletion cascades to the scan's assets/findings (FK on_delete=CASCADE);
      the persistent asset_inventory + Issue registers keep the long-term
      surface history, so pruning raw scans doesn't lose the over-time story.

    Returns the number of ScanSessions deleted.
    """
    from django.conf import settings

    if not getattr(settings, "SCAN_RETENTION_ENABLED", False):
        return 0

    from apps.core.engine.scans.models import ScanSession

    keep_n = getattr(settings, "SCAN_RETENTION_KEEP_PER_DOMAIN", 30)
    max_age_days = getattr(settings, "SCAN_RETENTION_MAX_AGE_DAYS", 180)
    age_cutoff = (
        django_tz.now() - django_tz.timedelta(days=max_age_days)
        if max_age_days and max_age_days > 0
        else None
    )
    terminal = ["completed", "failed", "partial", "cancelled"]

    # order_by() clears ScanSession.Meta.ordering — otherwise the ordering field
    # is added to the SELECT and defeats DISTINCT (one row per scan, not per domain).
    domains = list(
        ScanSession.objects.order_by().values_list("domain", flat=True).distinct()
    )
    to_delete = []
    for domain in domains:
        # Newest-first; only terminal scans are candidates for deletion.
        sessions = list(
            ScanSession.objects.filter(domain=domain, status__in=terminal)
            .order_by("-start_time")
            .values_list("id", "start_time")
        )
        for idx, (sid, start_time) in enumerate(sessions):
            if idx == 0:
                continue  # always keep the newest terminal scan for the domain
            if idx < keep_n:
                continue  # within the keep-N window
            if age_cutoff is not None and start_time >= age_cutoff:
                continue  # within the max-age window
            to_delete.append(sid)

    if not to_delete:
        return 0

    deleted, _ = ScanSession.objects.filter(id__in=to_delete).delete()
    # `deleted` counts cascaded rows too; report the ScanSession count explicitly.
    session_count = len(to_delete)
    logger.info(
        "[retention] Pruned %d old scan(s) across %d domain(s) (keep=%d, max_age_days=%s)",
        session_count, len(set(domains)), keep_n, max_age_days,
    )
    return session_count
