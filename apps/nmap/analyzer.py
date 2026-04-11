"""Nmap result analysis — parses XML, extracts vulners CVE findings."""

import logging
import xml.etree.ElementTree as ET

from apps.core.assets.models import Port
from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


def _extract_vulns(script_el) -> list[dict]:
    """Walk the vulners XML structure and yield {id, cvss, type, exploit} dicts.

    vulners outputs structured XML like:
        <script id="vulners">
          <table key="cpe:/a:openbsd:openssh:7.6p1">
            <table>
              <elem key="id">CVE-2018-15473</elem>
              <elem key="cvss">5.0</elem>
              <elem key="type">cve</elem>
              <elem key="is_exploit">false</elem>
            </table>
            ...
          </table>
        </script>
    """
    vulns = []
    # Iterate every nested table that contains an "id" elem
    for table in script_el.iter("table"):
        elems = {e.get("key"): (e.text or "").strip() for e in table.findall("elem")}
        if "id" not in elems:
            continue
        try:
            cvss = float(elems.get("cvss", "0") or "0")
        except ValueError:
            cvss = 0.0
        vulns.append({
            "id": elems["id"],
            "cvss": cvss,
            "type": elems.get("type", ""),
            "is_exploit": elems.get("is_exploit", "").lower() == "true",
        })
    return vulns


def _severity_from_cvss(score: float) -> str:
    """Map CVSS score to severity bucket."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def analyze(session, xml_outputs: dict[str, str]) -> list[Finding]:
    """
    Parse nmap XML outputs and build Finding instances.

    xml_outputs: dict of ip → xml string (one entry per nmap run)
    """
    if not xml_outputs:
        return []

    # Build a lookup of (address, port_number) → Port FK for this session
    port_map = {
        (p.address, p.port): p
        for p in Port.objects.filter(session=session)
    }

    findings: list[Finding] = []
    seen = set()  # (address, port, cve)

    for ip, xml_str in xml_outputs.items():
        if not xml_str:
            continue
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.warning(f"[nmap:{session.id}] XML parse error for {ip}: {e}")
            continue

        for host_el in root.findall("host"):
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", 0))
                service_el = port_el.find("service")
                service_name = service_el.get("name", "") if service_el is not None else ""
                version = ""
                if service_el is not None:
                    product = service_el.get("product", "")
                    ver = service_el.get("version", "")
                    version = f"{product} {ver}".strip()

                port_fk = port_map.get((ip, port_num))

                # Look for vulners script output
                for script_el in port_el.findall("script"):
                    if script_el.get("id") != "vulners":
                        continue

                    output = script_el.get("output", "")
                    vulns = _extract_vulns(script_el)
                    if not vulns:
                        continue

                    for v in vulns:
                        # Only keep CVEs (skip exploit-db / zdt entries)
                        if not v["id"].startswith("CVE-"):
                            continue

                        key = (ip, port_num, v["id"])
                        if key in seen:
                            continue
                        seen.add(key)

                        findings.append(Finding(
                            session=session,
                            source="nmap",
                            check_type="cve",
                            port=port_fk,
                            target=f"{ip}:{port_num}",
                            severity=_severity_from_cvss(v["cvss"]),
                            title=f"{v['id']} on {service_name or 'unknown'} {version}".strip(),
                            description=output[:2000],
                            extra={
                                "cve": v["id"],
                                "cvss_score": v["cvss"],
                                "service": service_name,
                                "version": version,
                                "nse_script": "vulners",
                                "port_number": port_num,
                                "address": ip,
                            },
                        ))

    return findings
