"""Takeover scanner — orchestrator: read Subdomains → subzy → save Findings.

Phase 3.5: runs after Phase 2 subdomain enumeration (subfinder/amass) and
before Phase 4 port scanning. Probing dangling DNS doesn't need port data —
only the subdomain list — so this slots in early.
"""

import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_takeover_check(session) -> list[Finding]:
    """Run subzy against all session subdomains and persist findings.

    Returns the list of newly-saved Finding objects (empty if nothing was
    detected, the binary is missing, or subzy returned no data).
    """
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info("[takeover_check:%s] no subdomains to check", session.id)
        return []

    logger.info(
        "[takeover_check:%s] running subzy against %d subdomains",
        session.id, len(subdomains),
    )

    records = collect(subdomains)
    findings = analyze(session, records)

    if not findings:
        return []

    Finding.objects.bulk_create(findings, ignore_conflicts=True)

    saved = list(Finding.objects.filter(
        session=session, source="takeover_check"
    ))
    logger.info(
        "[takeover_check:%s] saved %d takeover findings",
        session.id, len(saved),
    )
    return saved
