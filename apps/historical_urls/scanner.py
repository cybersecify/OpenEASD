"""Historical URLs scanner — orchestrator: read subdomains → collect → analyze → save."""

import logging

from apps.core.assets.models import Subdomain
from apps.core.web_assets.models import URL

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_historical_urls(session) -> list[URL]:
    """Collect and save historical URLs for the session's root domain and all subdomains."""
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info("[historical_urls:%s] no subdomains to query", session.id)
        return []

    # Always include the root domain itself — it's not a Subdomain row
    targets = list(dict.fromkeys([session.domain] + subdomains))

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
