"""Historical URL scanner — orchestrator: read Subdomains → discover URLs → save.

Phase 8.5: Runs after httpx (Phase 8) and before katana (Phase 9).
Feeds historical URLs into the same URL table for downstream scanning.
"""

import logging

from apps.core.assets.models import Subdomain
from apps.core.web_assets.models import URL
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_historical_urls(session) -> list[URL]:
    """
    Discover historical URLs for all subdomains in the session.

    Runs gau and waybackurls against each subdomain to surface forgotten
    endpoints, deprecated APIs, and removed-but-still-deployed paths.

    Args:
        session: The scan session object

    Returns:
        List of saved URL records
    """
    # Get all unique subdomains for this session
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info(f"[historical_urls:{session.id}] No subdomains to query")
        return []

    logger.info(
        f"[historical_urls:{session.id}] "
        f"Starting historical URL discovery for {len(subdomains)} subdomains"
    )

    # Collect historical URLs from gau and waybackurls
    urls = collect(session, subdomains)

    if not urls:
        logger.info(f"[historical_urls:{session.id}] No historical URLs found")
        return []

    # Analyze and create URL records
    objs = analyze(session, urls)

    if objs:
        # Bulk create, ignoring duplicates (same URL in same session)
        URL.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(URL.objects.filter(session=session, source="historical_urls"))
    logger.info(
        f"[historical_urls:{session.id}] "
        f"Saved {len(saved)} historical URLs "
        f"(from {len(subdomains)} subdomains)"
    )

    return saved
