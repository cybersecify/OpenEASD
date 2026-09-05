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

from .dbos_app import QUEUE_NAME

logger = logging.getLogger(__name__)

# Postgres handles concurrent writers, so more than one scan can run at once
# (bounded for target politeness + host RAM, not by a SQLite single-writer lock).
scan_queue = Queue(QUEUE_NAME, concurrency=getattr(settings, "DBOS_SCAN_CONCURRENCY", 2))


@DBOS.step()
def _prepare_assets(session_id: int) -> None:
    """Seed apex / copy parent assets — the pre-workflow setup run_scan does."""
    from apps.core.scans.pipeline import prepare_session_assets

    prepare_session_assets(session_id)


@DBOS.step()
def _run_phase_group(session_id: int, tools: list[str]) -> None:
    """Execute one phase group. Checkpointed: on resume a completed group is
    skipped and its tools are not re-run."""
    from apps.core.scans.pipeline import run_phase_group_for_session

    run_phase_group_for_session(session_id, tools)


@DBOS.step()
def _finalize(session_id: int) -> None:
    from apps.core.scans.pipeline import finalize_session_by_id

    finalize_session_by_id(session_id)


@DBOS.workflow(name="run_scan")
def run_scan_workflow(session_id: int) -> None:
    """Durable end-to-end scan. Phase groups run in registry order; each is a
    checkpointed step so a restart continues where it left off."""
    from apps.core.scans.pipeline import mark_session_running, phase_groups_for_session

    mark_session_running(session_id)
    _prepare_assets(session_id)
    for group in phase_groups_for_session(session_id):
        _run_phase_group(session_id, group)
    _finalize(session_id)
    logger.info("[dbos] scan workflow complete for session %s", session_id)


@DBOS.step()
def _run_ai_triage(session_id: int) -> None:
    from apps.core.ai.tasks import run_triage_and_summaries

    run_triage_and_summaries(session_id)


@DBOS.workflow(name="ai_triage")
def ai_triage_workflow(session_id: int) -> None:
    """Manual (re-)triage of a finished scan, durably."""
    _run_ai_triage(session_id)


@DBOS.step()
def _run_agent_step(root_session_id: int) -> None:
    from apps.core.ai.tasks import run_agent_step_safe

    run_agent_step_safe(root_session_id)


@DBOS.workflow(name="agent_step")
def agent_step_workflow(root_session_id: int) -> None:
    """One adaptive-orchestration decision step. The chain continues when a
    launched subscan's finalize enqueues the next agent_step."""
    _run_agent_step(root_session_id)


# --- Enqueue helpers (called from the web process via the client) -----------

def enqueue_scan(session_id: int) -> str:
    """Durably enqueue a scan. Deduplicated by session id so a double-submit
    can never start two runs of the same scan."""
    from dbos import EnqueueOptions

    from .dbos_app import get_client

    options: EnqueueOptions = {
        "workflow_name": "run_scan",
        "queue_name": QUEUE_NAME,
        "deduplication_id": f"scan-{session_id}",
        "duplication_policy": "return-existing",
    }
    handle = get_client().enqueue(options, session_id)
    return handle.workflow_id


def enqueue_ai_triage(session_id: int) -> str:
    from dbos import EnqueueOptions

    from .dbos_app import get_client

    options: EnqueueOptions = {
        "workflow_name": "ai_triage",
        "queue_name": QUEUE_NAME,
        "deduplication_id": f"triage-{session_id}",
        "duplication_policy": "return-existing",
    }
    handle = get_client().enqueue(options, session_id)
    return handle.workflow_id


def enqueue_agent_step(root_session_id: int) -> str:
    from dbos import EnqueueOptions

    from .dbos_app import get_client

    options: EnqueueOptions = {
        "workflow_name": "agent_step",
        "queue_name": QUEUE_NAME,
    }
    handle = get_client().enqueue(options, root_session_id)
    return handle.workflow_id
