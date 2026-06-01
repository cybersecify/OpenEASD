"""Historical URLs scanner — orchestrator: read subdomains → collect → analyze → save.

Phase 8.5: runs after httpx (Phase 8, current URL probing) and before
katana (Phase 9, live crawling). Historical sources surface forgotten
endpoints and deprecated APIs invisible to live-crawl-only scanning.
"""

import logging

from apps.core.assets.models import Subdomain
from apps.core.web_assets.models import URL

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_historical_urls(session) -> list[URL]:
    """Collect historical URLs for the session's root domain + all subdomains.

    Returns the list of newly-saved URL objects (empty if no subdomains exist,
    both binaries are missing, or neither source has history for this target).
    """
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info("[historical_urls:%s] no subdomains to query", session.id)
        return []

    # Always include the root domain itself — it's not a Subdomain row
    targets = [session.domain] + subdomains

    logger.info(
        "[historical_urls:%s] querying history for %d targets",
        session.id, len(targets),
    )

    raw_urls = collect(targets)
    objs = analyze(session, raw_urls)

    if not objs:
        return []

    URL.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(URL.objects.filter(session=session, source="historical_urls"))
    logger.info(
        "[historical_urls:%s] saved %d historical URLs",
        session.id, len(saved),
    )
    return saved
