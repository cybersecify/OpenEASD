"""AI work enqueued onto DBOS (replaces Django-Q).

Triage/summaries and each agent-orchestration step run as durable workflows.
The orchestration chain still advances one step at a time — a subscan's
finalize enqueues the next step — but each step is now a durable workflow, so
the pre-incremented iteration counter is backed by a checkpoint rather than a
best-effort queue task.
"""

import logging

logger = logging.getLogger(__name__)


def enqueue_triage(session_id: int) -> None:
    """Manual (re-)run of triage + summaries for a finished scan."""
    from apps.core.durable.workflows import enqueue_ai_triage

    enqueue_ai_triage(session_id)


def enqueue_agent_step(root_session_id: int) -> None:
    """Queue one orchestration step as a durable workflow."""
    from apps.core.durable.workflows import enqueue_agent_step as _enqueue

    _enqueue(root_session_id)


def run_triage_and_summaries(session_id: int) -> None:
    """Body executed inside the ai_triage DBOS step. Catches everything so a
    queued AI task can never fail the worker."""
    try:
        from apps.core.scans.models import ScanSession

        from .guard import is_ai_active
        from .models import AITriage
        from .summaries import run_summaries
        from .triage import run_triage

        if not is_ai_active():
            logger.info("[ai] triage for session %s skipped — gate closed", session_id)
            AITriage.objects.filter(session_id=session_id, status="running").delete()
            return
        session = ScanSession.objects.filter(id=session_id).first()
        if session is None:
            return
        result = run_triage(session)
        if result is None:
            AITriage.objects.filter(session=session, status="running").delete()
        run_summaries(session)
    except Exception:  # noqa: BLE001
        logger.exception("[ai] triage/summaries failed for session %s", session_id)


def run_agent_step_safe(root_session_id: int) -> None:
    """Body executed inside the agent_step DBOS step."""
    try:
        from .orchestrator import run_agent_step

        run_agent_step(root_session_id)
    except Exception:  # noqa: BLE001
        logger.exception("[ai] agent step failed for session %s", root_session_id)
