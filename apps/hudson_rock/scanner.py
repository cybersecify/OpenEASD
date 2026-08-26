"""Hudson Rock scanner — thin orchestrator: collect → analyze → save.

Additive intelligence. Any failure inside collect/analyze is swallowed and the
scan continues with zero findings — this tool must never fail a scan.
"""

import logging

from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_hudson_rock(session) -> list[Finding]:
    domain = session.domain  # CharField: "example.com"
    if not domain:
        logger.info("[hudson_rock:%s] no domain — skipping", session.id)
        return []

    try:
        data = collect(domain)
        findings = analyze(session, domain, data)
    except Exception:  # noqa: BLE001 — never let this tool fail a scan
        logger.exception("[hudson_rock:%s] unexpected error — skipping", session.id)
        return []

    if not findings:
        logger.info("[hudson_rock:%s] no infostealer exposure — nothing to save", session.id)
        return []

    Finding.objects.bulk_create(findings, ignore_conflicts=True)
    saved = list(Finding.objects.filter(session=session, source="hudson_rock"))
    logger.info("[hudson_rock:%s] saved %d infostealer findings", session.id, len(saved))
    return saved
