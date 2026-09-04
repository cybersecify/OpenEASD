"""Django-Q entry points for AI work that must not block an API request.

The cluster runs a single worker (SQLite single-writer), so every task here
must be short and self-terminating — nothing may wait on another task.
"""

import logging

from django_q.tasks import async_task

logger = logging.getLogger(__name__)


def enqueue_triage(session_id: int) -> None:
    """Manual (re-)run of triage + summaries for a finished scan."""
    async_task("apps.core.ai.tasks._run_triage_task", session_id)


def enqueue_agent_step(root_session_id: int) -> None:
    """Queue one orchestration step. Steps chain through the queue (a subscan's
    finalize enqueues the next one) so no task ever waits on another."""
    async_task("apps.core.ai.tasks._run_agent_step", root_session_id)


def _run_agent_step(root_session_id: int) -> None:
    """Worker entry — catches everything so a failed step can never crash the
    cluster; the pre-incremented iteration counter keeps the loop bounded even
    when a step dies here."""
    try:
        from .orchestrator import run_agent_step

        run_agent_step(root_session_id)
    except Exception:  # noqa: BLE001
        logger.exception("[ai] agent step failed for session %s", root_session_id)


def _run_triage_task(session_id: int) -> None:
    """Worker entry — catches everything (a queued AI task must never crash
    the cluster or mark hygiene noise in django-q's failure list)."""
    try:
        from apps.core.scans.models import ScanSession

        from .guard import is_ai_active
        from .summaries import run_summaries
        from .triage import run_triage

        from .models import AITriage

        if not is_ai_active():
            logger.info("[ai] triage task for session %s skipped — gate closed", session_id)
            AITriage.objects.filter(session_id=session_id, status="running").delete()
            return
        session = ScanSession.objects.filter(id=session_id).first()
        if session is None:
            return
        result = run_triage(session)
        if result is None:
            # Nothing to triage — clear any in-flight marker the API set.
            AITriage.objects.filter(session=session, status="running").delete()
        run_summaries(session)
    except Exception:  # noqa: BLE001
        logger.exception("[ai] manual triage task failed for session %s", session_id)
