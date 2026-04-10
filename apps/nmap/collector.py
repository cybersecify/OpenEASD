"""Nmap binary execution — data collection layer."""

import logging
import subprocess
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

BINARY = "/usr/bin/nmap"


def collect(session, domain: str) -> str:
    """Run nmap binary and return raw XML output string."""
    cmd = [BINARY, "-sV", "-T3", "-oX", "-", domain]
    logger.info(f"[nmap:{session.id}] Running service scan on {domain}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.stdout
    except FileNotFoundError:
        logger.error(f"[nmap:{session.id}] Binary not found: {BINARY}")
        return ""
    except subprocess.TimeoutExpired:
        logger.error(f"[nmap:{session.id}] Timed out")
        return ""
