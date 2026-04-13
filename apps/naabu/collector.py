"""Naabu binary execution — TCP port scan against IPs.

Port scan settings are configurable via Django admin (NaabuConfig model).
Defaults: top 100 ports, rate 1000 pps, 900s timeout.
"""

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

    from .models import NaabuConfig
    config = NaabuConfig.get()

    binary = getattr(settings, "TOOL_NAABU", "naabu")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [binary, "-list", tmp, "-json", "-silent"]

    # Port selection: custom_ports overrides top_ports
    if config.custom_ports.strip():
        cmd += ["-p", config.custom_ports.strip()]
    elif config.top_ports == "full":
        cmd += ["-p", "-"]
    else:
        cmd += ["-top-ports", config.top_ports]

    cmd += ["-rate", str(config.rate)]

    if config.exclude_ports.strip():
        cmd += ["-exclude-ports", config.exclude_ports.strip()]

    logger.info(
        f"[naabu:{session.id}] Scanning {len(targets)} targets "
        f"(ports={config.custom_ports.strip() or config.top_ports}, "
        f"rate={config.rate})"
    )

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=config.scan_timeout
        )
    except FileNotFoundError:
        logger.error(f"[naabu:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[naabu:{session.id}] Timed out after {config.scan_timeout}s")
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
