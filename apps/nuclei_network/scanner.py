"""Nuclei network scanner — orchestrator: collect -> analyze -> save findings."""

import logging

from apps.core.findings.models import Finding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_nuclei_network(session) -> list[Finding]:
    """
    Run nuclei with network templates against non-web ports.

    Targets: IP:port pairs with is_web=False
    Templates: network, dns, ftp, ssh, smtp, redis, mysql, etc.
    """
    records = collect(session)
    findings = analyze(session, records)

    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(
        f"[nuclei_network:{session.id}] {len(findings)} findings saved "
        f"from {len(records)} raw results"
    )
    return findings
