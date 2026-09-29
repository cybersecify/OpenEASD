"""Optional AI adjudication of verification verdicts.

Deterministic verification (apps/core/engine/verification) re-probes medium+
findings at finalize and stamps Finding.verification_status +
extra["verification"] (verdict/evidence/detail) — that machinery decides.

This module, run only when the AI layer is active, asks the model for a
SECOND OPINION on the deterministic verdict: a confidence score + rationale,
written to extra["verification"]["ai"]. AI advises, never decides — it never
touches verification_status or Finding.status, and a model failure is
swallowed exactly like every other AI hook (fail-graceful boundary lives in
hooks.py; this module mirrors that discipline for its own internal loop so
one bad finding never stops the rest).

Reuses the same audited path triage.py does: client.chat_json() writes one
metadata-only AIInvocation row per call and enforces the shared per-scan call
budget (CLOUDFLARE_AI_MAX_CALLS_PER_SCAN) — adjudication calls draw from the
same budget as triage/summaries, so a chatty scan can never make unbounded
LLM calls.
"""

import json
import logging

from pydantic import BaseModel, Field

from apps.core.constants import SEVERITY_RANK

from . import client, guard

logger = logging.getLogger(__name__)

# Hard cap independent of the shared call budget — keeps a single scan with
# hundreds of medium+ findings from turning adjudication into the dominant
# consumer of the per-scan budget triage/summaries also need.
_MAX_FINDINGS = 20
_MAX_DESCRIPTION_CHARS = 300

_SYSTEM_PROMPT = (
    "You are the analyst layer of OpenEASD, an external attack-surface scanner. "
    "A deterministic re-probe already produced a verification verdict for one "
    "finding. You give an advisory second opinion on that verdict only — you "
    "never override it. Reply with only the requested JSON object — no prose "
    "outside it."
)


class AdjudicationOut(BaseModel):
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(max_length=500)


def _eligible_findings(session) -> list:
    """verified/inconclusive findings at medium+ severity, most-severe first,
    stable by id, capped at _MAX_FINDINGS."""
    findings = [
        f for f in session.findings.all()
        if f.verification_status in ("verified", "inconclusive")
        and SEVERITY_RANK.get(f.severity, -1) >= SEVERITY_RANK.get("medium", 99)
    ]
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, -1), f.id))
    return findings[:_MAX_FINDINGS]


def _build_messages(finding) -> list[dict]:
    verification = (finding.extra or {}).get("verification") or {}
    payload = {
        "finding": {
            "severity": finding.severity,
            "source": finding.source,
            "check_type": finding.check_type,
            "title": finding.title[:200],
            "target": finding.target,
            "description": (finding.description or "")[:_MAX_DESCRIPTION_CHARS],
        },
        "deterministic_verification": {
            "verdict": finding.verification_status,
            "evidence": verification.get("evidence"),
            "detail": verification.get("detail"),
        },
    }
    instructions = (
        "Return JSON with:\n"
        "- confidence: 0.0-1.0, how confident a security analyst should be "
        "that the deterministic verdict above is correct, given the finding "
        "and evidence.\n"
        "- rationale: 1-2 sentences grounded in the finding's own data."
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": instructions + "\n\n" + json.dumps(payload)},
    ]


def _adjudicate_one(session, finding) -> dict | None:
    """One bounded, audited Cloudflare call for a single finding — same
    client.chat_json() path (and per-scan budget + AIInvocation audit row)
    run_triage uses. Returns None on any failure or budget exhaustion."""
    messages = _build_messages(finding)
    return client.chat_json(
        messages, AdjudicationOut, purpose="adjudication", session=session,
        finding_ids=[finding.id], max_tokens=300,
    )


def run_adjudication(session) -> None:
    """Annotate verified/inconclusive medium+ findings with an AI second
    opinion. No-op unless guard.is_ai_active(). Never raises, and never
    writes Finding.verification_status/status or creates Finding rows — only
    extra["verification"]["ai"] via save(update_fields=["extra"])."""
    if not guard.is_ai_active():
        return
    try:
        findings = _eligible_findings(session)
        n_annotated = 0
        for f in findings:
            try:
                ai = _adjudicate_one(session, f)
            except Exception:  # noqa: BLE001 — one bad finding must not stop the rest
                logger.exception("[adjudicate:%s] finding %s failed", session.id, f.id)
                continue
            if not ai:
                continue
            extra = dict(f.extra or {})
            v = dict(extra.get("verification") or {})
            v["ai"] = {"confidence": ai["confidence"], "rationale": ai["rationale"]}
            extra["verification"] = v
            f.extra = extra
            f.save(update_fields=["extra"])  # never touches verification_status/status
            n_annotated += 1
        logger.info("[adjudicate:%s] annotated %d/%d eligible findings",
                    session.id, n_annotated, len(findings))
    except Exception:  # noqa: BLE001 — AI must never fail a scan
        logger.exception("[adjudicate:%s] adjudication failed — scan unaffected", session.id)
