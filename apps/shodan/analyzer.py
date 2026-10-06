"""Shodan analyzer — turns normalized host records into shared Findings.

Up to two Findings per host:

  * ``shodan_exposure`` (info): the ports/services Shodan already sees exposed on
    the IP — "here is what any external observer can see about you without
    scanning." This is the passive-report exposure signal.
  * ``cve`` (medium): the known CVEs Shodan associates with the host. CVE ids are
    stored in ``extra["cve_ids"]`` so cve_intel (phase 12) enriches this Finding
    with EPSS scores + CISA KEV flags in place — feeding the prioritisation the
    report uses to flag pentest-worthy issues.

CVEs from Shodan's banner matching can be version-approximate, so the description
says so and points at the active nmap results for confirmation.
"""

import logging

from apps.core.data.findings.models import Finding
from apps.shodan.cdn import is_cdn_ip

logger = logging.getLogger(__name__)

_MAX_CVES_IN_DESC = 50


def _valid_cve(c) -> bool:
    return isinstance(c, str) and c.strip().upper().startswith("CVE-")


# HTTP/HTTPS ports — standard plus Cloudflare's alternate HTTP/HTTPS proxy ports.
# A host exposing ONLY these is just a web endpoint (behind a load balancer /
# CDN / reverse proxy), expected and not an actionable "exposed service" — and
# the web surface is already covered by the active httpx/web_checker/nuclei
# tools. Shodan's unique, actionable signal is NON-web services (databases,
# SSH/RDP, admin panels), so web-only hosts are collapsed into one info rollup.
_WEB_PORTS = frozenset({80, 443, 8080, 8443,
                        2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8880})


def _non_web_ports(ports) -> list:
    """The ports that are NOT standard/CDN web ports — the actionable ones. An
    unparseable port is treated as non-web (never hidden)."""
    out = []
    for p in ports or []:
        try:
            if int(p) not in _WEB_PORTS:
                out.append(int(p))
        except (TypeError, ValueError):
            out.append(p)
    return out


def _service_lines(host: dict) -> str:
    services = host.get("services") or []
    if services:
        lines = []
        for s in services:
            if not isinstance(s, dict):
                continue
            banner = f"{s.get('product') or ''} {s.get('version') or ''}".strip()
            port = s.get("port")
            transport = s.get("transport") or "tcp"
            lines.append(f"  - {port}/{transport} {banner}".rstrip())
        return "\n".join(lines)
    return "\n".join(f"  - {p}" for p in (host.get("ports") or []))


def analyze(session, results) -> list[Finding]:
    findings: list[Finding] = []
    web_only_hosts: list[dict] = []  # expose only web ports → one info rollup
    for host in results or []:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip")
        if not ip:
            continue
        ip = str(ip)
        ports = host.get("ports") or []
        services = host.get("services") or []
        vulns = sorted({c.strip().upper() for c in (host.get("vulns") or []) if _valid_cve(c)})
        tier = host.get("tier", "internetdb")

        # A CDN edge IP (Cloudflare/Fastly/…) is the CDN's shared infrastructure,
        # not the target's asset — ports 80/443 there are expected for every site
        # on that CDN, so an "exposed services" finding is pure noise. Skip it (a
        # leaked origin server is on a non-CDN IP and is still flagged). CVE
        # findings below are kept regardless (rare, high-signal).
        cdn = is_cdn_ip(ip)

        if ports or services:
            if cdn:
                logger.debug("shodan: skipping CDN-edge exposure finding for %s (%s)", ip, cdn)
            elif _non_web_ports(ports):
                # Actionable: a non-web port (DB/SSH/RDP/admin/...) is exposed.
                findings.append(Finding(
                    session=session,
                    source="shodan",
                    check_type="shodan_exposure",
                    severity="info",
                    target=ip,
                    title=f"Publicly exposed services on {ip} (via Shodan)",
                    description=(
                        f"Shodan's internet-wide scan data reports {len(ports)} open "
                        f"port(s) on {ip} visible to any external observer, without the "
                        f"target being scanned:\n{_service_lines(host)}"
                    ),
                    remediation=(
                        "Confirm each exposed service is intended to be internet-facing. "
                        "Firewall or restrict any that should not be public, and ensure "
                        "the rest are patched and access-controlled."
                    ),
                    extra={
                        "ip": ip,
                        "ports": ports,
                        "services": services,
                        "hostnames": host.get("hostnames") or [],
                        "tags": host.get("tags") or [],
                        "shodan_tier": tier,
                        "source_data": "shodan",
                    },
                ))
            else:
                # Web-only (80/443/CDN alt-ports): just a web endpoint behind a
                # load balancer / CDN — not an actionable exposure. Collapse.
                web_only_hosts.append({
                    "ip": ip,
                    "ports": list(ports),
                    "hostnames": host.get("hostnames") or [],
                    "shodan_tier": tier,
                })

        if vulns:
            shown = ", ".join(vulns[:_MAX_CVES_IN_DESC])
            overflow = "" if len(vulns) <= _MAX_CVES_IN_DESC else f" (+{len(vulns) - _MAX_CVES_IN_DESC} more)"
            findings.append(Finding(
                session=session,
                source="shodan",
                check_type="cve",
                severity="low",
                target=ip,
                title=f"{len(vulns)} known CVE(s) on exposed host {ip} (via Shodan)",
                description=(
                    "Shodan associates the following publicly known CVEs with the "
                    f"services exposed on {ip}. These are derived from Shodan's banner "
                    f"data and may need version confirmation:\n  {shown}{overflow}"
                ),
                remediation=(
                    "Verify the affected service versions and patch. Cross-check against "
                    "the active nmap scan, and prioritise using the EPSS/KEV enrichment "
                    "applied to this finding."
                ),
                extra={
                    "ip": ip,
                    "cve_ids": vulns,
                    "shodan_tier": tier,
                    "source_data": "shodan",
                },
            ))

    if web_only_hosts:
        findings.append(Finding(
            session=session,
            source="shodan",
            check_type="shodan_web_exposure",
            severity="info",
            target=f"{len(web_only_hosts)} host(s)",
            title=f"{len(web_only_hosts)} host(s) expose only standard web ports (via Shodan)",
            description=(
                f"Shodan reports {len(web_only_hosts)} of the target's resolved IPs "
                "serving only standard web ports (HTTP/HTTPS, including common "
                "CDN/proxy alt-ports) — expected for load-balanced or CDN-fronted web "
                "services, not an actionable exposure. Collapsed into this rollup so the "
                "report stays focused on non-web exposures (databases, SSH/RDP, admin). "
                "The full list is in extra."
            ),
            remediation=(
                "No action needed unless one of the listed hosts should not be "
                "internet-facing at all. The web surface itself is assessed by the "
                "active web tools (httpx / web_checker / nuclei)."
            ),
            extra={
                "hosts": web_only_hosts,
                "host_count": len(web_only_hosts),
                "source_data": "shodan",
            },
        ))

    return findings
