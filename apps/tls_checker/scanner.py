"""TLS Checker scanner — orchestrator: collect → analyze → save findings."""

import logging

from apps.core.findings.models import Finding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_tls_check(session) -> list[Finding]:
    """
    Check all open ports for TLS/encryption status and save findings.

    Covers both web ports (via httpx URL scheme) and non-web ports
    (via Python stdlib ssl/smtplib/imaplib/poplib/ftplib probes).
    Inherently insecure protocols (Telnet, rsh, etc.) are always flagged.
    """
    results = collect(session)
    findings = analyze(session, results)

    if findings:
        Finding.objects.bulk_create(findings)

    encrypted = sum(1 for r in results if r["has_tls"])
    plaintext = sum(1 for r in results if not r["has_tls"])
    logger.info(
        f"[tls_checker:{session.id}] {len(findings)} unencrypted findings "
        f"({encrypted} ports encrypted, {plaintext} plaintext out of {len(results)} checked)"
    )
    return findings
