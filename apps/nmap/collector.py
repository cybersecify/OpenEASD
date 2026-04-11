"""Nmap binary execution — service detection + vulners NSE script."""

import logging
import subprocess
from collections import defaultdict

from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session, ip_to_ports: dict[str, list[int]]) -> dict[str, str]:
    """
    Run nmap with -sV --script=vulners against each IP and its open ports.

    Returns a dict mapping ip → raw XML output (one nmap run per IP).
    """
    if not ip_to_ports:
        return {}

    binary = getattr(settings, "TOOL_NMAP", "nmap")
    results: dict[str, str] = {}

    for ip, ports in ip_to_ports.items():
        if not ports:
            continue
        port_list = ",".join(str(p) for p in sorted(set(ports)))
        cmd = [
            binary,
            "-sV",
            "--script=vulners",
            "--host-timeout=300s",
            "-p", port_list,
            "-oX", "-",   # XML to stdout
            "-Pn",        # skip host discovery (we already know it's alive)
            ip,
        ]
        logger.info(f"[nmap:{session.id}] Scanning {ip} ports {port_list}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
            results[ip] = proc.stdout
        except FileNotFoundError:
            logger.error(f"[nmap:{session.id}] Binary not found: {binary}")
            return results
        except subprocess.TimeoutExpired:
            logger.warning(f"[nmap:{session.id}] Timeout on {ip}")
            continue

    return results


def group_ports_by_ip(ports_qs) -> dict[str, list[int]]:
    """Group a Port queryset by IP address → list of port numbers."""
    grouped = defaultdict(list)
    for p in ports_qs:
        grouped[p.address].append(p.port)
    return dict(grouped)
