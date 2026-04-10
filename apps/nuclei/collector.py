"""Nuclei binary execution — data collection layer."""

import json
import logging
import os
import subprocess
import tempfile

logger = logging.getLogger(__name__)

BINARY = "/opt/homebrew/bin/nuclei"


def collect(session, targets: list) -> list[dict]:
    """Run nuclei binary against targets and return raw parsed JSON records."""
    if not targets:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [BINARY, "-list", tmp, "-json", "-silent"]
    logger.info(f"[nuclei:{session.id}] Scanning {len(targets)} targets")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError:
        logger.error(f"[nuclei:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[nuclei:{session.id}] Timed out")
        return []
    finally:
        os.unlink(tmp)

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            records.append(data)
        except json.JSONDecodeError:
            continue

    return records
