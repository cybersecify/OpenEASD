"""Report + alert summaries — thin consumers of the triage output.

Callers must hold the is_ai_active() gate. A failed call simply leaves the
AISummary row absent; the report and alert renderers treat absence as
"render exactly as before AI existed".
"""

import logging

from . import client, context
from .models import AISummary, AITriage
from .schemas import SummaryOut

logger = logging.getLogger(__name__)


def run_summaries(session) -> None:
    """Write AISummary rows (kinds: report, alert). Never raises."""
    overview = ""
    triage = AITriage.objects.filter(session=session, status="completed").first()
    if triage:
        overview = triage.overview

    model = client.resolve_model()
    for kind in ("report", "alert"):
        messages = context.build_summary_messages(session, kind, triage_overview=overview)
        purpose = "report_summary" if kind == "report" else "alert_summary"
        out = client.chat_json(
            messages, SummaryOut, purpose=purpose, session=session, max_tokens=800,
        )
        if out is None or not out.get("text", "").strip():
            logger.warning("[ai:%s] %s summary failed — leaving absent", session.id, kind)
            continue
        AISummary.objects.update_or_create(
            session=session, kind=kind,
            defaults={"text": out["text"].strip(), "model": model},
        )
        logger.info("[ai:%s] %s summary written", session.id, kind)
