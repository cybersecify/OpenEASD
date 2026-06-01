"""S3 bucket scanner — orchestrator: read domains → discover buckets → save findings.

Phase 4.5: Runs after naabu (port scanning) but before service detection.
Discovers publicly accessible S3 buckets by guessing bucket names.
"""

import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_s3_enum(session) -> list[Finding]:
    """
    Discover publicly accessible S3 buckets for all domains in the session.

    Guesses bucket names based on domain patterns and probes for public access.

    Args:
        session: The scan session object

    Returns:
        List of saved Finding records
    """
    # Get all unique domains for this session
    domains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not domains:
        logger.info(f"[s3_enum:{session.id}] No domains to check")
        return []

    logger.info(
        f"[s3_enum:{session.id}] "
        f"Starting S3 bucket discovery for {len(domains)} domains"
    )

    # Collect S3 buckets
    records = collect(session, domains)

    if not records:
        logger.info(f"[s3_enum:{session.id}] No public S3 buckets found")
        return []

    # Analyze and create findings
    objs = analyze(session, records)

    if objs:
        # Bulk create
        Finding.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(Finding.objects.filter(
        session=session,
        source="s3_enum",
    ))

    logger.info(
        f"[s3_enum:{session.id}] "
        f"Found {len(saved)} publicly accessible S3 buckets "
        f"(from {len(domains)} domains)"
    )

    return saved
