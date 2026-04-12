"""dnsx binary execution — resolves subdomains to IPs."""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session, subdomains: list[str]) -> list[dict]:
    """Run dnsx against a list of subdomains. Returns raw resolution records.

    Each record: {"host": "api.example.com", "a": [...], "aaaa": [...]}
    """
    if not subdomains:
        return []

    binary = getattr(settings, "TOOL_DNSX", "dnsx")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        tmp = f.name

    cmd = [binary, "-l", tmp, "-a", "-aaaa", "-resp", "-json", "-silent"]
    logger.info(f"[dnsx:{session.id}] Resolving {len(subdomains)} subdomains")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.error(f"[dnsx:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[dnsx:{session.id}] Timed out")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0:
        logger.warning(f"[dnsx:{session.id}] Exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"[dnsx:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "").strip().lower()
            if host:
                records.append({
                    "host": host,
                    "a": data.get("a", []) or [],
                    "aaaa": data.get("aaaa", []) or [],
                })
        except json.JSONDecodeError:
            continue

    return records
