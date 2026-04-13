"""Nuclei binary execution — data collection layer.

Runs the nuclei binary against non-web ports discovered by naabu/service_detection.
Uses service-aware tag selection: maps Port.service to nuclei template tags so only
relevant templates run per session.
"""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings
from apps.core.assets.models import Port

logger = logging.getLogger(__name__)

BINARY = getattr(settings, "TOOL_NUCLEI", "nuclei")
TIMEOUT = 3600  # 1 hour max per scan

# Baseline tags always included regardless of services found
_BASELINE_TAGS = {"misconfig", "exposures", "default-login", "cves"}

# Maps partial service name (lowercase) → nuclei tag
# ssh is intentionally excluded — handled by ssh_checker
_SERVICE_TAG_MAP = {
    "ftp":           "ftp",
    "smtp":          "smtp",
    "smtps":         "smtp",
    "redis":         "redis",
    "mysql":         "mysql",
    "postgresql":    "postgresql",
    "postgres":      "postgresql",
    "mongodb":       "mongodb",
    "ldap":          "ldap",
    "ldaps":         "ldap",
    "vnc":           "vnc",
    "rdp":           "rdp",
    "ms-wbt-server": "rdp",
    "elasticsearch": "elasticsearch",
    "memcached":     "memcached",
    "smb":           "smb",
    "microsoft-ds":  "smb",
    "mssql":         "mssql",
    "ms-sql":        "mssql",
    "cassandra":     "cassandra",
    "rabbitmq":      "rabbitmq",
    "amqp":          "rabbitmq",
}


def _build_tags(ports) -> set[str]:
    """
    Build a set of nuclei tags from the services detected on the given ports.

    Performs case-insensitive partial matching against _SERVICE_TAG_MAP.
    Always includes _BASELINE_TAGS. Skips ssh (owned by ssh_checker).
    Falls back to _BASELINE_TAGS only if no services are recognised.
    """
    tags = set(_BASELINE_TAGS)
    for port in ports:
        service = (port.service or "").lower().strip()
        if not service:
            continue
        for key, tag in _SERVICE_TAG_MAP.items():
            if key in service:
                tags.add(tag)
                break
    return tags


def collect(session) -> list[dict]:
    """
    Run nuclei with service-aware network templates against non-web ports.

    Builds IP:port targets from Port objects with is_web=False, derives
    nuclei tags from detected service names, and runs nuclei in JSONL mode.

    Returns list of raw nuclei JSON records (one per finding).
    """
    ports = list(Port.objects.filter(session=session, state="open", is_web=False))
    if not ports:
        logger.info(f"[nuclei_network:{session.id}] No non-web ports to scan")
        return []

    tags = _build_tags(ports)
    targets = sorted(set(f"{p.address}:{p.port}" for p in ports))

    logger.info(
        f"[nuclei_network:{session.id}] Scanning {len(targets)} non-web targets "
        f"with tags={sorted(tags)}"
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [
        BINARY, "-list", tmp,
        "-pt", "network,ssl",
        "-tags", ",".join(sorted(tags)),
        "-severity", "critical,high,medium,low",
        "-jsonl", "-silent", "-no-color",
    ]

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
