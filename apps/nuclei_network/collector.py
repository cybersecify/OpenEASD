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
from apps.core.workflows.exceptions import ToolBinaryMissing
from apps.core.workflows.proc import run_capped

logger = logging.getLogger(__name__)

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
    binary = getattr(settings, "TOOL_NUCLEI", "nuclei")

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
        binary, "-list", tmp,
        "-pt", "network,ssl",
        "-tags", ",".join(sorted(tags)),
        "-severity", "critical,high,medium,low",
        # Same peak-memory bound as the web run (see apps/nuclei/collector.py).
        "-bulk-size", str(getattr(settings, "NUCLEI_BULK_SIZE", 15)),
        "-jsonl", "-silent", "-no-color",
    ]

    stdout, stderr = "", ""
    try:
        # run_capped (not subprocess.run) so an escaped interactsh/resolver helper
        # can't hold the stdout pipe open and wedge the worker on timeout — the
        # same anti-hang fix the web nuclei collector already had.
        from apps.core.workflows.proc_env import go_memory_env
        result = run_capped(cmd, TIMEOUT, env=go_memory_env())
        stdout, stderr = result.stdout, result.stderr
    except FileNotFoundError:
        logger.error(f"[nuclei_network:{session.id}] Binary not found: {binary}")
        raise ToolBinaryMissing(f"nuclei binary not found: {binary}")
    except subprocess.TimeoutExpired as exc:
        # Deliver the network findings nuclei wrote before the wall (run_capped
        # attaches partial stdout to exc.output) instead of discarding them and
        # reporting a false-clean 0. Logged so the truncation is visible.
        stdout = exc.output or ""
        logger.warning(
            f"[nuclei_network:{session.id}] Time-limited at {TIMEOUT}s — delivering "
            f"{len(stdout.splitlines())} partial output lines"
        )
    finally:
        os.unlink(tmp)

    # Surface stderr regardless of exit code (nuclei exits 0 with template-load
    # warnings) so silent under-coverage is visible.
    if stderr and stderr.strip():
        logger.warning(f"[nuclei_network:{session.id}] stderr: {stderr[:500]}")

    records = []
    for line in stdout.strip().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            logger.debug(f"[nuclei_network:{session.id}] Skipping non-JSON line: {line[:100]}")

    logger.info(f"[nuclei_network:{session.id}] Parsed {len(records)} raw findings")
    return records
