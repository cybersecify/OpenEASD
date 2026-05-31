"""katana binary execution — crawls a list of URLs and returns discovered endpoints."""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session, urls: list[str]) -> list[dict]:
    if not urls:
        return []

    binary = getattr(settings, "TOOL_KATANA", "katana")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        tmp = f.name

    cmd = [
        binary,
        "-list", tmp,
        "-jsonl",
        "-silent",
        "-depth", "3",
        "-timeout", "30",
    ]
    logger.info(f"[katana:{session.id}] Crawling {len(urls)} seed URLs")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.error(f"[katana:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[katana:{session.id}] Timed out")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0:
        logger.warning(f"[katana:{session.id}] Exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"[katana:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records
