"""js_secrets scanner — orchestrator: collect JS URLs -> gitleaks -> save findings."""

import logging

from apps.core.findings.models import Finding
from apps.core.web_assets.models import URL
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_js_secrets(session) -> list[Finding]:
    """Scan the session's discovered JavaScript assets for hardcoded secrets.

    Pulls every URL discovered by the web-exposure phase (httpx / historical /
    katana), lets the collector filter to .js files, fetch them, and run
    gitleaks, then saves one Finding per unique secret.
    """
    urls = list(URL.objects.filter(session=session).values_list("url", flat=True))
    if not urls:
        logger.info(f"[js_secrets:{session.id}] No URLs to scan")
        return []

    records = collect(session, urls)
    findings = analyze(session, records)

    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(
        f"[js_secrets:{session.id}] {len(findings)} findings saved "
        f"from {len(records)} raw gitleaks results"
    )
    return findings
