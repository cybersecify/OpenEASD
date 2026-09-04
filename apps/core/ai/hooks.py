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
