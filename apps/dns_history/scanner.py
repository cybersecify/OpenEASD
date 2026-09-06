"""Historical-DNS scanner — thin orchestrator: collect → analyze → save.

Additive intelligence. Any failure inside collect/analyze is swallowed and the
scan continues with zero findings — this tool must never fail a scan.
"""

import logging

from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_dns_history(session) -> list[Finding]:
    domain = session.domain  # CharField: "example.com"
    if not domain:
        logger.info("[dns_history:%s] no domain — skipping", session.id)
        return []

    try:
        records = collect(domain)
        findings = analyze(session, domain, records)
    except Exception:  # noqa: BLE001 — never let this tool fail a scan
        logger.exception("[dns_history:%s] unexpected error — skipping", session.id)
        return []

    if not findings:
        logger.info("[dns_history:%s] no historical records — nothing to save", session.id)
        return []

    Finding.objects.bulk_create(findings, ignore_conflicts=True)
    saved = list(Finding.objects.filter(session=session, source="dns_history"))
    logger.info("[dns_history:%s] saved %d historical-DNS findings", session.id, len(saved))
    return saved
