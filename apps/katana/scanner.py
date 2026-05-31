"""katana scanner — orchestrator: read httpx URLs → crawl → save new URLs."""

import logging

from apps.core.web_assets.models import URL
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_katana(session) -> list[URL]:
    """Crawl URLs already discovered by httpx, save new endpoints found."""
    seed_urls = list(
        URL.objects.filter(session=session, source="httpx").values_list("url", flat=True)
    )
    if not seed_urls:
        logger.info(f"[katana:{session.id}] No httpx URLs to crawl")
        return []

    records = collect(session, seed_urls)
    objs = analyze(session, records)

    if objs:
        URL.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(URL.objects.filter(session=session, source="katana"))
    logger.info(f"[katana:{session.id}] Discovered {len(saved)} new URLs from {len(seed_urls)} seeds")
    return saved
