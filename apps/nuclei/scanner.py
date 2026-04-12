"""Nuclei scanner — orchestrator: collect -> analyze -> save findings."""

import logging

from apps.core.findings.models import Finding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_nuclei(session) -> list[Finding]:
    """
    Run nuclei vulnerability scan against web URLs and save findings.

    Targets all URLs discovered by httpx (Phase 5). Nuclei uses its
    community templates to detect CVEs, misconfigurations, exposures,
    default credentials, and other web vulnerabilities.
    """
    records = collect(session)
    findings = analyze(session, records)

    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(
        f"[nuclei:{session.id}] {len(findings)} findings saved "
        f"from {len(records)} raw results"
    )
    return findings
