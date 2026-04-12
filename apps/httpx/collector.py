"""httpx binary execution — probes web on host:port pairs."""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session, host_ports: list[str]) -> list[dict]:
    """
    Run httpx against a list of host:port targets. Returns raw web records.

    Each record (subset of httpx fields):
        {
            "url": "https://1.2.3.4:443",
            "scheme": "https",
            "host": "1.2.3.4",
            "port": "443",
            "status_code": 200,
            "title": "Example",
            "webserver": "nginx",
            "content_length": 1234,
        }
    """
    if not host_ports:
        return []

    binary = getattr(settings, "TOOL_HTTPX", "httpx")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(host_ports))
        tmp = f.name

    cmd = [
        binary,
        "-l", tmp,
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-web-server",
        "-content-length",
        "-no-color",
        "-timeout", "10",
    ]
    logger.info(f"[httpx:{session.id}] Probing {len(host_ports)} host:port pairs")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        logger.error(f"[httpx:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[httpx:{session.id}] Timed out")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0:
        logger.warning(f"[httpx:{session.id}] Exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"[httpx:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records
