"""Gowitness analyzer — store screenshot metadata and link to URLs."""

import logging
import os
import hashlib

from django.db import models

from apps.core.web_assets.models import URL

logger = logging.getLogger(__name__)


class URLScreenshot(models.Model):
    """Screenshot metadata linked to a URL."""

    url = models.ForeignKey(
        URL,
        on_delete=models.CASCADE,
        related_name="screenshots",
    )
    screenshot_path = models.CharField(max_length=500)
    http_status = models.IntegerField(null=True, blank=True)
    page_title = models.CharField(max_length=500, blank=True)
    captured_at = models.DateTimeField(auto_now_add=True)
    file_size = models.IntegerField(default=0)

    class Meta:
        unique_together = ["url", "screenshot_path"]

    def __str__(self):
        return f"Screenshot for {self.url.url}"


def analyze(session, records: list[dict], output_dir: str) -> list[URLScreenshot]:
    """
    Parse gowitness results and create URLScreenshot records.

    Args:
        session: The scan session object
        records: List of gowitness result records
        output_dir: Directory containing screenshot files

    Returns:
        List of URLScreenshot model instances
    """
    if not records:
        return []

    # Get URLs for this session
    urls = {
        url.url: url
        for url in URL.objects.filter(session=session)
    }

    objs = []

    for record in records:
        try:
            url_str = record.get("url", "")
            if not url_str:
                continue

            # Find matching URL record
            url_obj = urls.get(url_str)
            if not url_obj:
                continue

            # Get screenshot file path
            screenshot_file = record.get("screenshot", "")
            if not screenshot_file:
                continue

            # Construct full path
            screenshot_path = os.path.join(output_dir, screenshot_file)
            if not os.path.exists(screenshot_path):
                logger.warning(f"Screenshot file not found: {screenshot_path}")
                continue

            # Get file size
            file_size = os.path.getsize(screenshot_path)

            # Create URLScreenshot instance
            obj = URLScreenshot(
                url=url_obj,
                screenshot_path=screenshot_path,
                http_status=record.get("status-code"),
                page_title=record.get("title", ""),
                file_size=file_size,
            )
            objs.append(obj)

        except Exception as e:
            logger.warning(f"Failed to process gowitness record: {e}")
            continue

    logger.info(
        f"[gowitness:{session.id}] "
        f"Analyzed {len(records)} records → {len(objs)} screenshot records"
    )

    return objs
