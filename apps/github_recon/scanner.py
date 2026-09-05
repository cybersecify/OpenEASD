"""GitHub Org Recon scanner — thin orchestrator: collect -> analyze -> save.

Passive additive intelligence. Any failure inside collect/analyze is swallowed and
the scan continues with zero findings — this tool must never fail a scan.
"""

import logging

from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_github_recon(session) -> list[Finding]:
    domain = session.domain  # CharField: "example.com"
    if not domain:
        logger.info("[github_recon:%s] no domain — skipping", session.id)
        return []

    try:
        data = collect(domain)
        findings = analyze(session, domain, data)
    except Exception:  # noqa: BLE001 — never let this tool fail a scan
        logger.exception("[github_recon:%s] unexpected error — skipping", session.id)
        return []

    if not findings:
        logger.info("[github_recon:%s] no GitHub exposure — nothing to save", session.id)
        return []

    Finding.objects.bulk_create(findings, ignore_conflicts=True)
    saved = list(Finding.objects.filter(session=session, source="github_recon"))
    logger.info("[github_recon:%s] saved %d GitHub recon finding(s)", session.id, len(saved))
    return saved
