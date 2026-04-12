"""Nuclei network scanner — runs nuclei with network templates against non-web ports.

Targets non-web ports (is_web=False) with protocol-specific templates:
  - Default credentials (Redis, MongoDB, FTP anonymous, etc.)
  - Service misconfigurations (open DNS resolver, SMTP open relay)
  - Protocol-level vulnerabilities
  - Banner-based detection
"""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)

BINARY = getattr(settings, "TOOL_NUCLEI", "nuclei")
TIMEOUT = 3600  # 1 hour max (same as web nuclei)


def collect(session) -> list[dict]:
    """
    Run nuclei with network templates against non-web ports.

    Builds IP:port targets from Port objects with is_web=False.
    Returns list of raw nuclei JSON records.
    """
    from apps.core.assets.models import Port

    ports = list(Port.objects.filter(session=session, state="open", is_web=False))
    if not ports:
        logger.info(f"[nuclei_network:{session.id}] No non-web ports to scan")
        return []

    # Build targets as IP:port
    targets = sorted(set(f"{p.address}:{p.port}" for p in ports))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [BINARY, "-list", tmp, "-type", "network", "-jsonl", "-silent", "-no-color"]
    logger.info(f"[nuclei_network:{session.id}] Scanning {len(targets)} non-web targets")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except FileNotFoundError:
        logger.error(f"[nuclei_network:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[nuclei_network:{session.id}] Timed out after {TIMEOUT}s")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0 and result.stderr:
        logger.warning(f"[nuclei_network:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            logger.debug(f"[nuclei_network:{session.id}] Skipping non-JSON line: {line[:100]}")

    logger.info(f"[nuclei_network:{session.id}] Parsed {len(records)} raw findings")
    return records
