"""Durable scan + AI workflows.

Each scan is a DBOS workflow whose phases are checkpointed steps: a worker that
crashes or restarts RESUMES the scan at the first phase that had not finished,
instead of the whole thing being reaped as failed (which is what
`reap_stuck_scans` did under Django-Q). Django ORM calls live inside steps —
DBOS checkpoints to its own `dbos` schema, the app data goes to the app tables.
"""

import logging

from dbos import DBOS, Queue
from django.conf import settings

from .constants import QUEUE_NAME
from .task import durable_task

logger = logging.getLogger(__name__)

# Postgres handles concurrent writers, so more than one scan can run at once
# (bounded for target politeness + host RAM, not by a SQLite single-writer lock).
scan_queue = Queue(QUEUE_NAME, concurrency=getattr(settings, "DBOS_SCAN_CONCURRENCY", 2))


@DBOS.step()
def _prepare_assets(session_id: int) -> None:
    """Seed apex / copy parent assets — the pre-workflow setup run_scan does."""
    from apps.core.engine.scans.pipeline import prepare_session_assets

    prepare_session_assets(session_id)


@DBOS.step()
def _run_phase_group(session_id: int, tools: list[str]) -> None:
    """Execute one phase group. Checkpointed: on resume a completed group is
    skipped and its tools are not re-run."""
    from apps.core.engine.scans.pipeline import run_phase_group_for_session

    run_phase_group_for_session(session_id, tools)


@DBOS.step()
def _finalize(session_id: int) -> None:
    from apps.core.engine.scans.pipeline import finalize_session_by_id

    finalize_session_by_id(session_id)


@DBOS.workflow(name="run_scan")
def run_scan_workflow(session_id: int) -> None:
    """Durable end-to-end scan. Phase groups run in registry order; each is a
    checkpointed step so a restart continues where it left off."""
    from apps.core.engine.scans.pipeline import mark_session_running, phase_groups_for_session

    mark_session_running(session_id)
    _prepare_assets(session_id)
    for group in phase_groups_for_session(session_id):
        _run_phase_group(session_id, group)
    _finalize(session_id)
    logger.info("[dbos] scan workflow complete for session %s", session_id)


# No dedupe (F2): a "triage-{id}" deduplication_id with return-existing made a
# manual re-triage return the prior (completed) workflow and silently no-op,
# defeating the whole point of the re-run endpoint. Each manual run now enqueues
# a fresh workflow; the API endpoint serializes concurrent runs atomically
# (run_triage_now). Matches agent_step, which also carries no dedupe.
@durable_task("ai_triage")
def ai_triage(session_id: int) -> None:
    """Manual (re-)triage of a finished scan, durably (one-step task)."""
    from apps.core.console.ai.tasks import run_triage_and_summaries

    run_triage_and_summaries(session_id)


@durable_task("agent_step")
def agent_step(root_session_id: int) -> None:
    """One adaptive-orchestration decision step (one-step task). The chain
    continues when a launched subscan's finalize enqueues the next agent_step."""
    from apps.core.console.ai.tasks import run_agent_step_safe

    run_agent_step_safe(root_session_id)


# --- Enqueue helpers (called from the web process via the client) -----------

def enqueue_scan(session_id: int) -> str:
    """Durably enqueue a scan. Deduplicated by session id so a double-submit
    can never start two runs of the same scan."""
    from dbos import EnqueueOptions

    from .client import get_client

    options: EnqueueOptions = {
        "workflow_name": "run_scan",
        "queue_name": QUEUE_NAME,
        "deduplication_id": f"scan-{session_id}",
        "duplication_policy": "return-existing",
    }
    handle = get_client().enqueue(options, session_id)
    return handle.workflow_id


def enqueue_ai_triage(session_id: int) -> str:
    """Thin wrapper kept for callers; delegates to the durable task's .delay()."""
    return ai_triage.delay(session_id)


def enqueue_agent_step(root_session_id: int) -> str:
    """Thin wrapper kept for callers; delegates to the durable task's .delay()."""
    return agent_step.delay(root_session_id)


# ---------------------------------------------------------------------------
# Scheduled (cron) workflows — replace the Django-Q qcluster scheduler for the
# unattended-scanning backbone. Registered when the worker imports this module;
# they run only in the launched worker process. Each is a no-op unless
# SCHEDULED_SCANS_ENABLED, so the master switch still makes a deployment
# durably manual-only.
# ---------------------------------------------------------------------------

_DAILY_CRON = "{m} {h} * * *".format(
    m=getattr(settings, "SCAN_DAILY_MINUTE", 0),
    h=getattr(settings, "SCAN_DAILY_HOUR", 2),
)
_MONITORING_SWEEP_CRON = getattr(settings, "MONITORING_SWEEP_CRON", "*/15 * * * *")
_WATCHDOG_CRON = getattr(settings, "WATCHDOG_CRON", "*/15 * * * *")
_TOKEN_PURGE_CRON = getattr(settings, "TOKEN_PURGE_CRON", "0 3 * * *")


def _scheduled_scans_enabled() -> bool:
    return getattr(settings, "SCHEDULED_SCANS_ENABLED", True)


# Plain guard+delegate helpers (unit-testable without a launched DBOS engine).
# The @scheduled workflows below are thin cron glue over these.

def run_daily_scan_if_enabled() -> None:
    if not _scheduled_scans_enabled():
        return
    from apps.core.engine.scheduler.scheduler import daily_scan

    daily_scan()


def run_monitoring_sweep_if_enabled() -> None:
    if not _scheduled_scans_enabled():
        return
    from apps.core.engine.scheduler.scheduler import run_due_monitoring_scans

    run_due_monitoring_scans()


def run_user_scans_sweep_if_enabled() -> None:
    if not _scheduled_scans_enabled():
        return
    from apps.core.engine.scheduler.scheduler import run_due_user_scans

    run_due_user_scans()


_USER_SCHED_SWEEP_CRON = getattr(settings, "USER_SCHEDULE_SWEEP_CRON", "* * * * *")


@DBOS.scheduled(_DAILY_CRON)
@DBOS.workflow(name="scheduled_daily_scan")
def scheduled_daily_scan(scheduled_time, actual_time) -> None:
    run_daily_scan_if_enabled()


@DBOS.scheduled(_MONITORING_SWEEP_CRON)
@DBOS.workflow(name="scheduled_monitoring_sweep")
def scheduled_monitoring_sweep(scheduled_time, actual_time) -> None:
    """Enqueue a scan for each active, authorized, monitored domain that is due."""
    run_monitoring_sweep_if_enabled()


@DBOS.scheduled(_USER_SCHED_SWEEP_CRON)
@DBOS.workflow(name="scheduled_user_scans_sweep")
def scheduled_user_scans_sweep(scheduled_time, actual_time) -> None:
    """Fire user-created one-time/recurring scans that are due (ScheduledScan)."""
    run_user_scans_sweep_if_enabled()


@DBOS.scheduled(_WATCHDOG_CRON)
@DBOS.workflow(name="scheduled_watchdog")
def scheduled_watchdog(scheduled_time, actual_time) -> None:
    from apps.core.engine.scheduler.scheduler import reap_stuck_scans

    reap_stuck_scans()


@DBOS.scheduled(_TOKEN_PURGE_CRON)
@DBOS.workflow(name="scheduled_token_purge")
def scheduled_token_purge(scheduled_time, actual_time) -> None:
    from apps.core.engine.scheduler.scheduler import purge_expired_blacklisted_tokens

    purge_expired_blacklisted_tokens()
