"""Nmap scanner — orchestrator: collect → analyze → save NmapFindings.

Reads non-web ports from apps.core.assets.Port (those with NO matching URL
record from httpx, accounting for CDN-fronted hostnames that resolve to
multiple IPs), runs nmap with vulners NSE, stores findings linked back
to the Port asset.
"""

import logging
from collections import defaultdict

from apps.core.assets.models import IPAddress, Port, URL
from apps.core.findings.models import Finding
from .collector import collect, group_ports_by_ip
from .analyzer import analyze

logger = logging.getLogger(__name__)


def _web_pairs_for_session(session) -> set[tuple[str, int]]:
    """Return the set of (ip_address, port_number) pairs confirmed as web.

    A pair is considered web if ANY URL record exists for any IP that the
    URL's parent subdomain resolves to. This handles CDN-fronted hostnames
    where one Cloudflare hostname maps to multiple A records — httpx probes
    the hostname once but ALL IPs behind it should be classified as web.
    """
    web_pairs: set[tuple[str, int]] = set()

    # Single query: fetch all IPs grouped by subdomain_id (avoids N+1)
    ip_by_subdomain: dict[int, list[str]] = defaultdict(list)
    for row in IPAddress.objects.filter(session=session).values("subdomain_id", "address"):
        if row["subdomain_id"]:
            ip_by_subdomain[row["subdomain_id"]].append(row["address"])

    urls = URL.objects.filter(session=session, port_number__isnull=False)
    for url in urls:
        if url.subdomain_id:
            for ip in ip_by_subdomain.get(url.subdomain_id, []):
                web_pairs.add((ip, url.port_number))
        # Also pair the URL's own host (in case host was a raw IP, no subdomain)
        if url.host:
            web_pairs.add((url.host, url.port_number))

    return web_pairs


def run_nmap(session) -> list[Finding]:
    """Run nmap NSE vulners against non-web ports."""
    web_pairs = _web_pairs_for_session(session)

    all_open = Port.objects.filter(session=session, state="open")
    ports_qs = [p for p in all_open if (p.address, p.port) not in web_pairs]

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
