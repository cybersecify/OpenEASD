"""Service detection — enriches Port records with service names via nmap -sV.

Runs after port discovery (naabu) and before all scanning tools. Updates
Port.service, Port.version, and Port.is_web so downstream tools have
accurate service information.
"""

import logging
import subprocess
from collections import defaultdict

from django.conf import settings

from .parser import parse_services

logger = logging.getLogger(__name__)

# Services that indicate a web port (Port.is_web=True)
WEB_SERVICES = frozenset({
    "http", "https", "http-proxy", "https-alt", "http-alt",
})

TIMEOUT = 120  # seconds per host


def _group_ports_by_ip(ports) -> dict[str, list]:
    """Group Port objects by IP address → list of (port_number, port_obj)."""
    grouped: dict[str, list] = defaultdict(list)
    for p in ports:
        grouped[p.address].append((p.port, p))
    return dict(grouped)


def _run_nmap_sv(session_id, ip: str, port_list: str) -> str:
    """Run nmap -sV --version-light on an IP and return raw XML output."""
    binary = getattr(settings, "TOOL_NMAP", "nmap")
    cmd = [
        binary,
        "-sV", "--version-light",   # fast service detection (intensity 2)
        "--host-timeout", f"{TIMEOUT}s",
        "-p", port_list,
        "-oX", "-",                 # XML to stdout
        "-Pn",                      # skip host discovery
        ip,
    ]
    logger.info(f"[service_detection:{session_id}] Detecting services on {ip} ports {port_list}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT + 30)
        if proc.returncode != 0 and proc.stderr:
            logger.warning(f"[service_detection:{session_id}] {ip} stderr: {proc.stderr[:300]}")
        return proc.stdout
    except FileNotFoundError:
        logger.error(f"[service_detection:{session_id}] Binary not found: {binary}")
        return ""
    except subprocess.TimeoutExpired:
        logger.warning(f"[service_detection:{session_id}] Timeout on {ip}")
        return ""


def detect_services(session) -> int:
    """
    Run nmap -sV --version-light on all open ports, update Port.service,
    Port.version, and Port.is_web. Returns count of ports updated.
    """
    from apps.core.assets.models import Port

    open_ports = list(Port.objects.filter(session=session, state="open"))
    if not open_ports:
        logger.info(f"[service_detection:{session.id}] No open ports")
        return 0

    ip_groups = _group_ports_by_ip(open_ports)
    # Build port_num → Port object lookup for updates
    port_lookup: dict[tuple[str, int], "Port"] = {
        (p.address, p.port): p for p in open_ports
    }

    updated = 0
    for ip, port_entries in ip_groups.items():
        port_list = ",".join(str(p) for p, _ in sorted(set(port_entries)))
        xml = _run_nmap_sv(session.id, ip, port_list)
        if not xml:
            continue

        services = parse_services(xml)
        for svc in services:
            port_obj = port_lookup.get((svc["ip"], svc["port"]))
            if not port_obj:
                continue
            if not svc["service"]:
                continue

            is_web = svc["service"].lower() in WEB_SERVICES
            Port.objects.filter(id=port_obj.id).update(
                service=svc["service"],
                version=svc["version"],
                is_web=is_web,
            )
            updated += 1
            logger.debug(
                f"[service_detection:{session.id}] {svc['ip']}:{svc['port']} "
                f"→ {svc['service']} {svc['version']} (web={is_web})"
            )

    logger.info(f"[service_detection:{session.id}] Updated {updated}/{len(open_ports)} ports")
    return updated
