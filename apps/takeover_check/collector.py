"""Subdomain takeover detection — wraps subzy to detect dangling DNS records."""

import json
import logging
import subprocess
import shutil
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session, subdomains: list[str]) -> list[dict]:
    """
    Run subzy against a list of subdomains to detect takeover vulnerabilities.

    Args:
        session: The scan session object
        subdomains: List of subdomain strings to check

    Returns:
        List of takeover vulnerability records
    """
    if not subdomains:
        return []

    binary = getattr(settings, "TOOL_SUBZY", "subzy")

    if not shutil.which(binary):
        logger.warning(f"subzy binary not found at '{binary}'")
        return []

    # Write subdomains to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        tmp = f.name

    try:
        # Run subzy
        cmd = [
            binary,
            "run",
            "--targets", tmp,
            "--hide_fails",
            "--timeout", "30",
            "--json",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=len(subdomains) * 60,  # 60s per subdomain max
            stdin=subprocess.DEVNULL,
        )

        if result.returncode != 0:
            logger.warning(f"subzy failed: {result.stderr[:300]}")
            return []

        # Parse JSON output
        records = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                records.append(record)
            except json.JSONDecodeError:
                continue

        logger.info(f"subzy found {len(records)} potential takeovers")
        return records

    except subprocess.TimeoutExpired:
        logger.warning("subzy timed out")
        return []
    except Exception as e:
        logger.error(f"subzy error: {e}")
        return []
    finally:
        # Clean up temp file
        try:
            import os
            os.unlink(tmp)
        except OSError:
            pass
