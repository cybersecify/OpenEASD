import logging
import subprocess
import xml.etree.ElementTree as ET

from .models import ServiceResult

logger = logging.getLogger(__name__)

BINARY = "/usr/bin/nmap"


def run_nmap(session, domain: str) -> list:
    """Run nmap service detection against domain, save results, return ServiceResult list."""
    cmd = [BINARY, "-sV", "-T3", "-oX", "-", domain]
    logger.info(f"[nmap:{session.id}] Running service scan on {domain}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        logger.error(f"[nmap:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[nmap:{session.id}] Timed out")
        return []

    objs = []
    try:
        root = ET.fromstring(result.stdout)
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

    if objs:
        ServiceResult.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(session.services.all())
    logger.info(f"[nmap:{session.id}] Found {len(saved)} services")
    return saved
