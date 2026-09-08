"""Pipeline hooks — the ONLY symbols apps/core/scans/pipeline.py imports.

This module is the fail-graceful boundary (safety invariant 5): every public
hook catches ALL exceptions, so no AI failure mode can change a scan's
outcome. With the gate closed (no keys / disabled / no consent) each hook is
a cheap no-op and the scan is byte-identical to pre-AI behavior (invariant 1).
"""

import logging

logger = logging.getLogger(__name__)


def run_ai_post_scan(session) -> None:
    """Triage + summaries, inline in the scan task. Called from
    _finalize_session after build_insights and before _dispatch_alerts (so
    alerts can embed the summary). Bounded: at most 4 LLM calls, each with a
    hard client timeout."""
    try:
        from .guard import is_ai_active
        if not is_ai_active():
            return
        from .models import AISettings
        cfg = AISettings.get()
        if cfg.triage_enabled:
            from .triage import run_triage
            run_triage(session)
        if cfg.summaries_enabled:
            from .summaries import run_summaries
            run_summaries(session)
    except Exception:  # noqa: BLE001 — AI must never fail a scan
        logger.exception("[ai:%s] post-scan AI step failed — scan unaffected", session.id)


def maybe_start_agent(session) -> None:
    """Enqueue the first orchestration step for a finished root scan. Called
    as the last line of _finalize_session — after alerts, so the root scan's
    user-visible output never waits on the agent."""
    try:
        from .guard import is_ai_active
        if not is_ai_active():
            return
        from .models import AISettings
        if not AISettings.get().orchestration_enabled:
            return
        if session.scan_type == "subscan" or session.status not in ("completed", "partial"):
            return
        from .tasks import enqueue_agent_step
        enqueue_agent_step(session.id)
        logger.info("[ai:%s] agent step enqueued", session.id)
    except Exception:  # noqa: BLE001
        logger.exception("[ai:%s] agent start failed — scan unaffected", session.id)


def maybe_continue_agent(sub_session) -> None:
    """Resume a running agent chain when one of its subscans finalizes. This
    is how subscan results feed back: the next step's context includes the
    subscan's findings."""
    try:
        from .models import AgentAction
        action = (
            AgentAction.objects.filter(
                subscan_session=sub_session, agent_run__status="running"
            )
            .select_related("agent_run")
            .first()
        )
        if action is None:
            return
        from .tasks import enqueue_agent_step
        enqueue_agent_step(action.agent_run.root_session_id)
        logger.info("[ai:%s] agent chain resumed after subscan %s",
                    action.agent_run.root_session_id, sub_session.id)
    except Exception:  # noqa: BLE001
        logger.exception("[ai:%s] agent continue failed — subscan unaffected", sub_session.id)
