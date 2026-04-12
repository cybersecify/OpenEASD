"""Subfinder binary execution — data collection layer."""

import json
import logging
import re
import subprocess

from django.conf import settings

logger = logging.getLogger(__name__)

# RFC 1035 / RFC 1123 — must have at least one dot and a valid TLD (2+ alpha chars)
_VALID_HOSTNAME = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def collect(session) -> list[dict]:
    """Run subfinder binary and return raw parsed JSON records."""
    domain = session.domain
    if not _VALID_HOSTNAME.match(domain):
        logger.error(f"[subfinder:{session.id}] Invalid domain: {domain!r}")
        return []

    binary = getattr(settings, "TOOL_SUBFINDER", "subfinder")
    cmd = [binary, "-d", domain, "-json", "-silent"]
    logger.info(f"[subfinder:{session.id}] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.error(f"[subfinder:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[subfinder:{session.id}] Timed out")
        return []

    if result.returncode != 0:
        logger.warning(f"[subfinder:{session.id}] Exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"[subfinder:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "").strip()
            if host:
                records.append({"host": host, "ip": data.get("ip") or None})
        except json.JSONDecodeError:
            host = line.strip()
            if host:
                records.append({"host": host, "ip": None})

    return records
