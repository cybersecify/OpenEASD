"""Post-scan triage — ranks the session's findings with rationale.

Callers must hold the is_ai_active() gate; this module assumes it. Failure
semantics: an LLM failure records AITriage(status="failed") so the UI can
offer a retry, but never raises past run_triage.
"""

import logging

from . import client, context
from .models import AISettings, AITriage, AITriageItem
from .schemas import TriageOut

logger = logging.getLogger(__name__)


def run_triage(session) -> "AITriage | None":
    """Triage the session's findings. Returns the AITriage row, or None when
    there was nothing to triage. Never raises."""
    cfg = AISettings.get()
    findings = context.select_findings(session, cfg.max_findings_per_prompt)
    if not findings:
        logger.info("[ai:%s] no non-info findings — skipping triage", session.id)
        return None

    by_id = {f.id: f for f in findings}
    messages = context.build_triage_messages(session, findings)
    out = client.chat_json(
        messages, TriageOut, purpose="triage", session=session,
        finding_ids=sorted(by_id), max_tokens=3000,
    )

    if out is None:
        triage, _ = AITriage.objects.update_or_create(
            session=session, defaults={"status": "failed", "model": client.resolve_model()},
        )
        triage.items.all().delete()
        logger.warning("[ai:%s] triage LLM call failed", session.id)
        return triage

    triage, _ = AITriage.objects.update_or_create(
        session=session,
        defaults={
            "status": "completed",
            "model": client.resolve_model(),
            "overview": out.get("overview", ""),
        },
    )
    triage.items.all().delete()  # re-runs replace, never append

    items, seen, rank = [], set(), 1
    for item in out.get("items", []):
        finding = by_id.get(item.get("finding_id"))
        if finding is None or finding.id in seen:
            continue  # hallucinated or duplicated id — drop silently
        seen.add(finding.id)
        items.append(AITriageItem(
            triage=triage,
            finding=finding,
            finding_key=f"{finding.source}:{finding.check_type}:{finding.title}"[:600],
            rank=rank,
            priority=item["priority"],
            rationale=item.get("rationale", ""),
        ))
        rank += 1
    AITriageItem.objects.bulk_create(items)

    logger.info("[ai:%s] triage completed — %d/%d findings ranked",
                session.id, len(items), len(findings))
    return triage
