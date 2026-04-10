"""Subfinder binary execution — data collection layer."""

import json
import logging
import subprocess

logger = logging.getLogger(__name__)

BINARY = "/opt/homebrew/bin/subfinder"


def collect(session) -> list[dict]:
    """Run subfinder binary and return raw parsed JSON records."""
    domain = session.domain
    cmd = [BINARY, "-d", domain, "-json", "-silent"]
    logger.info(f"[subfinder:{session.id}] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.error(f"[subfinder:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[subfinder:{session.id}] Timed out")
        return []

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
