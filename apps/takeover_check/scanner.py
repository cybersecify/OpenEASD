"""Subdomain takeover scanner — orchestrator: read Subdomains → detect takeovers → save findings.

Phase 3.5: Runs after dnsx (needs CNAME records) but before port scanning.
Detects dangling DNS records pointing to unclaimed cloud resources.
"""

import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_takeover_check(session) -> list[Finding]:
    """
    Check all subdomains for takeover vulnerabilities.

    Runs subzy against discovered subdomains to detect dangling DNS records
    pointing to unclaimed cloud resources (S3, Heroku, GitHub Pages, etc.).

    Args:
        session: The scan session object

    Returns:
        List of saved Finding records
    """
    # Get all unique subdomains for this session
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info(f"[takeover_check:{session.id}] No subdomains to check")
        return []

    logger.info(
        f"[takeover_check:{session.id}] "
        f"Starting takeover detection for {len(subdomains)} subdomains"
    )

    # Collect takeover vulnerabilities
    records = collect(session, subdomains)

    if not records:
        logger.info(f"[takeover_check:{session.id}] No takeovers detected")
        return []

    # Analyze and create findings
    objs = analyze(session, records)

    if objs:
        # Bulk create
        Finding.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(Finding.objects.filter(
        session=session,
        source="takeover_check",
    ))

    logger.info(
        f"[takeover_check:{session.id}] "
        f"Found {len(saved)} takeover vulnerabilities "
        f"(from {len(subdomains)} subdomains)"
    )

    return saved
