"""Naabu binary execution — top 100 TCP port scan against IPs."""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session, targets: list[str]) -> list[dict]:
    """Run naabu against a list of IPs/hosts. Returns raw port records.

    Each record: {"host": "1.2.3.4", "port": 443, "protocol": "tcp"}
    """
    if not targets:
        return []

    binary = getattr(settings, "TOOL_NAABU", "naabu")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [binary, "-list", tmp, "-top-ports", "100", "-json", "-silent"]
    logger.info(f"[naabu:{session.id}] Scanning {len(targets)} targets (top 100 TCP)")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except FileNotFoundError:
        logger.error(f"[naabu:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[naabu:{session.id}] Timed out")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0:
        logger.warning(f"[naabu:{session.id}] Exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"[naabu:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            host = (data.get("ip") or data.get("host") or "").strip()
            port = data.get("port")
            if host and port:
                records.append({
                    "host": host,
                    "port": int(port),
                    "protocol": data.get("protocol", "tcp"),
                })
        except (json.JSONDecodeError, ValueError):
            continue

    return records
