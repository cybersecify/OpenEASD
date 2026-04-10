"""Nmap result analysis — XML parsing and model building layer."""

import logging
import xml.etree.ElementTree as ET

from .models import ServiceResult

logger = logging.getLogger(__name__)


def analyze(session, xml_output: str, domain: str) -> list:
    """Parse nmap XML output and build ServiceResult model instances."""
    objs = []
    if not xml_output:
        return objs

    try:
        root = ET.fromstring(xml_output)
        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            host = addr_el.get("addr", "") if addr_el is not None else domain
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                objs.append(ServiceResult(
                    session=session,
                    host=host,
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    state="open",
                    service_name=service_el.get("name", "") if service_el is not None else "",
                    version=service_el.get("version", "") if service_el is not None else "",
                ))
    except ET.ParseError as e:
        logger.warning(f"[nmap:{session.id}] XML parse error: {e}")

    return objs
