"""Web Checker scanner — orchestrator: collect -> analyze -> save findings."""

import logging

from apps.core.data.findings.models import Finding
from .collector import collect, collect_security_txt
from .analyzer import analyze, security_txt_findings

logger = logging.getLogger(__name__)


def run_web_check(session) -> list[Finding]:
    """
    Check all web URLs for security header and configuration issues.

    Inspects HTTP responses for missing security headers (CSP, XFO, etc.),
    cookie flag issues, CORS misconfigurations, server disclosure, and
    directory listings, plus the primary domain's security.txt (RFC 9116)
    responsible-disclosure policy.
    """
    results = collect(session)
    findings = analyze(session, results)

    # Responsible disclosure — one security.txt check on the primary domain.
    findings.extend(security_txt_findings(collect_security_txt(session), session))

    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(
        f"[web_checker:{session.id}] {len(findings)} findings from "
        f"{len(results)} URLs"
    )
    return findings
