import json
import logging
import subprocess
import tempfile
import os

from .models import PortResult

logger = logging.getLogger(__name__)

BINARY = "/opt/homebrew/bin/naabu"


def run_naabu(session, targets: list) -> list:
    """Run naabu port scan against targets, save results, return PortResult list."""
    if not targets:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [BINARY, "-list", tmp, "-json", "-silent"]
    logger.info(f"[naabu:{session.id}] Scanning {len(targets)} targets")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        logger.error(f"[naabu:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[naabu:{session.id}] Timed out")
        return []
    finally:
        os.unlink(tmp)

    objs = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "").strip()
            port = data.get("port")
            if host and port:
                objs.append(PortResult(
                    session=session,
                    host=host,
                    port=int(port),
                    protocol=data.get("protocol", "tcp"),
                ))
        except (json.JSONDecodeError, ValueError):
            continue

    if objs:
        PortResult.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(session.port_results.all())
    logger.info(f"[naabu:{session.id}] Found {len(saved)} open ports")
    return saved
