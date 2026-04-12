"""Nuclei binary execution — data collection layer.

Runs the nuclei binary against web URLs discovered by httpx (Phase 5).
Nuclei scans for web vulnerabilities using community templates:
  - CVEs, misconfigurations, exposures, default credentials
  - Tech-specific checks (WordPress, Jira, etc.)
  - Security header issues, open redirects, SSRF, etc.
"""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)

BINARY = getattr(settings, "TOOL_NUCLEI", "nuclei")
TIMEOUT = 3600  # 1 hour max per scan


def collect(session) -> list[dict]:
    """
    Run nuclei against all web URLs from the httpx phase.

    Builds targets from URL.objects for this session, writes them to a temp
    file, and runs nuclei in JSON output mode.

    Returns list of raw nuclei JSON records (one per finding).
    """
    from apps.core.assets.models import URL

    urls = list(URL.objects.filter(session=session).values_list("url", flat=True))
    if not urls:
        logger.info(f"[nuclei:{session.id}] No URLs to scan")
        return []

    # Deduplicate
    targets = sorted(set(urls))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [BINARY, "-list", tmp, "-json", "-silent", "-no-color"]
    logger.info(f"[nuclei:{session.id}] Scanning {len(targets)} web targets")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except FileNotFoundError:
        logger.error(f"[nuclei:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[nuclei:{session.id}] Timed out after {TIMEOUT}s")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0 and result.stderr:
        logger.warning(f"[nuclei:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            records.append(data)
        except json.JSONDecodeError:
            logger.debug(f"[nuclei:{session.id}] Skipping non-JSON line: {line[:100]}")
            continue

    logger.info(f"[nuclei:{session.id}] Parsed {len(records)} raw findings")
    return records
