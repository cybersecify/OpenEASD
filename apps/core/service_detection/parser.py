"""Parse nmap XML output for service detection results."""

import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


def parse_services(xml_str: str) -> list[dict]:
    """
    Parse nmap -sV XML output and extract service info per port.

    Returns list of dicts:
      [{"ip": str, "port": int, "service": str, "version": str}, ...]
    """
    if not xml_str:
        return []

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        logger.warning(f"[service_detection] XML parse error: {e}")
        return []

    results = []
    for host_el in root.findall("host"):
        # Get IP address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_num = int(port_el.get("portid", 0))
            service_el = port_el.find("service")

            if service_el is not None:
                service_name = service_el.get("name", "")
                product = service_el.get("product", "")
                ver = service_el.get("version", "")
                version = f"{product} {ver}".strip()
            else:
                service_name = ""
                version = ""

            results.append({
                "ip": ip,
                "port": port_num,
                "service": service_name,
                "version": version,
            })

    return results
