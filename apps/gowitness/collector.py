"""Gowitness screenshot capture — takes screenshots of URLs using headless Chromium."""

import json
import logging
import os
import subprocess
import shutil
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session, urls: list[str], output_dir: str) -> list[dict]:
    """
    Run gowitness against a list of URLs and capture screenshots.

    Args:
        session: The scan session object
        urls: List of URL strings to screenshot
        output_dir: Directory to store screenshots and metadata

    Returns:
        List of screenshot metadata records
    """
    if not urls:
        return []

    binary = getattr(settings, "TOOL_GOWITNESS", "gowitness")

    if not shutil.which(binary):
        logger.warning(f"gowitness binary not found at '{binary}'")
        return []

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Write URLs to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        tmp = f.name

    try:
        # Run gowitness
        cmd = [
            binary,
            "file",
            "-f", tmp,
            "-P", output_dir,
            "--json-file", os.path.join(output_dir, "results.json"),
            "--timeout", "30",
            "--delay", "2",
            "--no-stdout",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=len(urls) * 60,  # 60s per URL max
            stdin=subprocess.DEVNULL,
        )

        if result.returncode != 0:
            logger.warning(f"gowitness failed: {result.stderr[:300]}")
            return []

        # Parse results
        results_file = os.path.join(output_dir, "results.json")
        if not os.path.exists(results_file):
            logger.warning("gowitness results.json not found")
            return []

        with open(results_file, "r") as f:
            records = json.load(f)

        logger.info(f"gowitness captured {len(records)} screenshots")
        return records

    except subprocess.TimeoutExpired:
        logger.warning("gowitness timed out")
        return []
    except Exception as e:
        logger.error(f"gowitness error: {e}")
        return []
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp)
        except OSError:
            pass
