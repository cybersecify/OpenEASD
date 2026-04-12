"""Nmap scanner — orchestrator: collect → analyze → save findings.

Reads non-web ports from apps.core.assets.Port (is_web=False),
runs nmap with vulners NSE, stores findings linked back to the Port asset.
"""

import logging

from apps.core.assets.models import Port
from apps.core.findings.models import Finding
from .collector import collect, group_ports_by_ip
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_nmap(session) -> list[Finding]:
    """Run nmap NSE vulners against non-web ports."""
    ports_qs = list(Port.objects.filter(session=session, state="open", is_web=False))

    if not ports_qs:
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
        Finding.objects.bulk_create(findings)

    logger.info(f"[nmap:{session.id}] {len(findings)} CVE findings")
    return findings
