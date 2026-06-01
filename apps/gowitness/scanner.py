"""Gowitness scanner — orchestrator: read URLs → capture screenshots → save metadata.

Phase 10: Runs after httpx + katana, before nuclei web vuln scan.
Captures screenshots of all discovered URLs for visual triage.
"""

import logging
import os

from django.conf import settings

from apps.core.web_assets.models import URL
from .collector import collect
from .analyzer import analyze, URLScreenshot

logger = logging.getLogger(__name__)


def run_gowitness(session) -> list[URLScreenshot]:
    """
    Capture screenshots for all URLs in the session.

    Runs gowitness against discovered URLs to create visual artifacts
    for triage and demo purposes.

    Args:
        session: The scan session object

    Returns:
        List of saved URLScreenshot records
    """
    # Get all URLs for this session
    urls = list(
        URL.objects.filter(session=session)
        .values_list("url", flat=True)
        .distinct()
    )

    if not urls:
        logger.info(f"[gowitness:{session.id}] No URLs to screenshot")
        return []

    # Create output directory
    data_dir = getattr(settings, "DATA_DIR", "data")
    output_dir = os.path.join(data_dir, "screenshots", str(session.id))
    os.makedirs(output_dir, exist_ok=True)

    logger.info(
        f"[gowitness:{session.id}] "
        f"Starting screenshot capture for {len(urls)} URLs"
    )

    # Collect screenshots
    records = collect(session, urls, output_dir)

    if not records:
        logger.info(f"[gowitness:{session.id}] No screenshots captured")
        return []

    # Analyze and create records
    objs = analyze(session, records, output_dir)

    if objs:
        # Bulk create
        URLScreenshot.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(URLScreenshot.objects.filter(url__session=session))
    total_size = sum(s.file_size for s in saved)

    logger.info(
        f"[gowitness:{session.id}] "
        f"Saved {len(saved)} screenshots "
        f"({total_size / 1024 / 1024:.1f} MB total)"
    )

    return saved
