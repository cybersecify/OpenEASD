"""typosquat scanner — thin orchestrator: collect -> analyze -> save.

Passive threat-surface intelligence. Any failure inside collect/analyze is
swallowed and the scan continues with zero findings — this tool must never fail
a scan.
"""

import logging

from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_typosquat(session) -> list[Finding]:
    try:
        results = collect(session)
        findings = analyze(session, results)
    except Exception:  # noqa: BLE001 — never let this tool fail a scan
        logger.exception("[typosquat:%s] unexpected error — skipping", session.id)
        return []

    if not findings:
        logger.info("[typosquat:%s] no registered lookalikes — nothing to save", session.id)
        return []

    Finding.objects.bulk_create(findings, ignore_conflicts=True)
    saved = list(Finding.objects.filter(session=session, source="typosquat"))
    logger.info("[typosquat:%s] saved %d lookalike finding(s)", session.id, len(saved))
    return saved
