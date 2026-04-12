"""Web Checker scanner — orchestrator: collect -> analyze -> save findings."""

import logging

from apps.core.findings.models import Finding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_web_check(session) -> list[Finding]:
    """
    Check all web URLs for security header and configuration issues.

    Inspects HTTP responses for missing security headers (CSP, XFO, etc.),
    cookie flag issues, CORS misconfigurations, server disclosure, and
    directory listings.
    """
    results = collect(session)
    findings = analyze(session, results)

    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(
        f"[web_checker:{session.id}] {len(findings)} findings from "
        f"{len(results)} URLs"
    )
    return findings
