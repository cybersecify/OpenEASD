"""SSH Checker scanner — orchestrator: collect -> analyze -> save findings."""

import logging

from apps.core.findings.models import Finding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_ssh_check(session) -> list[Finding]:
    """
    Check all SSH ports for security configuration weaknesses and save findings.

    Probes host key strength, key exchange / cipher / MAC algorithms,
    authentication methods, and protocol version support.
    """
    results = collect(session)
    findings = analyze(session, results)

    if findings:
        Finding.objects.bulk_create(findings)

    reachable = sum(1 for r in results if r["probe_success"])
    logger.info(
        f"[ssh_checker:{session.id}] {len(findings)} findings from "
        f"{reachable} reachable SSH ports (of {len(results)} total)"
    )
    return findings
