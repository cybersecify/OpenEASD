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

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_MAX_CVES_IN_DESC = 50


def _valid_cve(c) -> bool:
    return isinstance(c, str) and c.strip().upper().startswith("CVE-")


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

        if ports or services:
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

        if vulns:
            shown = ", ".join(vulns[:_MAX_CVES_IN_DESC])
            overflow = "" if len(vulns) <= _MAX_CVES_IN_DESC else f" (+{len(vulns) - _MAX_CVES_IN_DESC} more)"
            findings.append(Finding(
                session=session,
                source="shodan",
                check_type="cve",
                severity="medium",
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

    return findings
