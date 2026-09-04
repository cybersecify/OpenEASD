"""github_secrets scanner — thin orchestrator: collect -> analyze -> save.

Passive additive intelligence. The GitHub-API side is fail-graceful (never
raises); the only errors that propagate are a missing / timed-out gitleaks
binary (a real config error), exactly like js_secrets.
"""

import logging

from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_github_secrets(session) -> list[Finding]:
    records = collect(session)
    findings = analyze(session, records)

    if not findings:
        logger.info("[github_secrets:%s] no GitHub secrets found — nothing to save", session.id)
        return []

    Finding.objects.bulk_create(findings, ignore_conflicts=True)
    saved = list(Finding.objects.filter(session=session, source="github_secrets"))
    logger.info("[github_secrets:%s] saved %d GitHub-secret finding(s)", session.id, len(saved))
    return saved
