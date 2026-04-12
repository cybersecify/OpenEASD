"""Service detection — classifies ports as web or non-web.

Two-step probe per port:
  1. TLS handshake (socket + ssl) → encrypted or plaintext?
  2. HTTP request (requests) → web or non-web?

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
      3. Neither responds  → is_web=False

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

        # Try HTTPS first, then HTTP
        if _probe_http(ip, port_num, "https"):
            service = "https"
            is_web = True
        elif _probe_http(ip, port_num, "http"):
            service = "http"
            is_web = True
        else:
            service = ""
            is_web = False

        if service or is_web != p.is_web:
            Port.objects.filter(id=p.id).update(service=service, is_web=is_web)
            updated += 1
            logger.debug(
                f"[service_detection:{session.id}] {ip}:{port_num} → "
                f"{service if service else 'unknown'} (web={is_web})"
            )

    logger.info(f"[service_detection:{session.id}] {updated}/{len(open_ports)} ports classified")
    return updated
