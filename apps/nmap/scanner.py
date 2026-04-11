"""Nmap scanner — orchestrator: collect → analyze → save NmapFindings.

Reads non-web ports from apps.core.assets.Port (those with NO matching URL
record from httpx), runs nmap with vulners NSE, stores findings linked
back to the Port asset.
"""

import logging

from apps.core.assets.models import Port
from .models import NmapFinding
from .collector import collect, group_ports_by_ip
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_nmap(session) -> list[NmapFinding]:
    """Run nmap NSE vulners against non-web ports (Ports without a URL record)."""
    # Non-web = open Port with no URL record (httpx couldn't probe it as web)
    ports_qs = Port.objects.filter(session=session, state="open", urls__isnull=True).distinct()
    if not ports_qs.exists():
        logger.info(f"[nmap:{session.id}] No non-web ports to scan")
        return []

    ip_to_ports = group_ports_by_ip(ports_qs)
    logger.info(
        f"[nmap:{session.id}] Scanning {sum(len(v) for v in ip_to_ports.values())} "
        f"non-web ports across {len(ip_to_ports)} hosts"
    )

    xml_outputs = collect(session, ip_to_ports)
    findings = analyze(session, xml_outputs)

    if findings:
        NmapFinding.objects.bulk_create(findings)

    logger.info(f"[nmap:{session.id}] {len(findings)} CVE findings")
    return findings
