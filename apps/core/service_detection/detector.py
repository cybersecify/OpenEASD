"""Service detection — classifies ports as web or non-web.

Probes each port with HTTP/HTTPS requests. If the probe fails on a
common web port (80, 443, etc.), assumes web to avoid false non-web
classification (CDN-fronted services reject requests by IP).

Primary output: Port.is_web (True/False)
Secondary output: Port.service ("http", "https", or "")
"""

import logging

import requests
import urllib3

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROBE_TIMEOUT = 3

WEB_SERVICES = frozenset({"http", "https"})

# Common web ports — if probe fails/times out, assume web rather than
# letting nmap scan them (CDN services reject raw IP requests)
COMMON_WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000, 5000})


def _probe_http(ip: str, port: int, scheme: str) -> bool:
    """Try an HTTP request with the given scheme. Returns True if it responds."""
    try:
        requests.head(
            f"{scheme}://{ip}:{port}",
            timeout=PROBE_TIMEOUT,
            verify=False,
            allow_redirects=False,
            headers={"User-Agent": "openeasd-service-probe/1.0"},
        )
        return True
    except requests.RequestException:
        return False


def detect_services(session) -> int:
    """
    Probe all open ports to classify as web or non-web.

    For each port:
      1. Try HTTPS request → if responds, service="https", is_web=True
      2. Try HTTP request  → if responds, service="http", is_web=True
      3. Neither responds + common web port → assume web (is_web=True)
      4. Neither responds + uncommon port → is_web=False

    Returns count of ports updated.
    """
    from apps.core.assets.models import Port

    open_ports = list(Port.objects.filter(session=session, state="open"))
    if not open_ports:
        logger.info(f"[service_detection:{session.id}] No open ports")
        return 0

    updated = 0
    for p in open_ports:
        ip = p.address
        port_num = p.port

        if _probe_http(ip, port_num, "https"):
            service = "https"
            is_web = True
        elif _probe_http(ip, port_num, "http"):
            service = "http"
            is_web = True
        elif port_num in COMMON_WEB_PORTS:
            service = "https" if port_num == 443 else "http"
            is_web = True
        else:
            service = ""
            is_web = False

        if service or is_web != p.is_web:
            Port.objects.filter(id=p.id).update(service=service, is_web=is_web)
            updated += 1
            logger.debug(
                f"[service_detection:{session.id}] {ip}:{port_num} → "
                f"{service if service else 'non-web'} (web={is_web})"
            )

    logger.info(f"[service_detection:{session.id}] {updated}/{len(open_ports)} ports classified")
    return updated
