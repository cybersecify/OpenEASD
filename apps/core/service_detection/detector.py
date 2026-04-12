"""Service detection — classifies ports as web or non-web.

Probes each port with HTTP/HTTPS requests using the subdomain hostname
(for CDN/SNI compatibility) with IP fallback.

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


def _probe_http(host: str, port: int, scheme: str) -> bool:
    """Try an HTTP request with the given scheme. Returns True if it responds."""
    try:
        requests.head(
            f"{scheme}://{host}:{port}",
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

    Uses subdomain hostname for probing (CDN/SNI compatible), falls back
    to raw IP if no hostname is available.

    For each port:
      1. Try HTTPS request → if responds, service="https", is_web=True
      2. Try HTTP request  → if responds, service="http", is_web=True
      3. Neither responds  → is_web=False

    Returns count of ports updated.
    """
    from apps.core.assets.models import Port

    open_ports = list(
        Port.objects.filter(session=session, state="open")
        .select_related("ip_address__subdomain")
    )
    if not open_ports:
        logger.info(f"[service_detection:{session.id}] No open ports")
        return 0

    updated = 0
    for p in open_ports:
        ip = p.address
        port_num = p.port

        # Prefer subdomain hostname (CDN/SNI compatible), fall back to IP
        host = ip
        if p.ip_address and p.ip_address.subdomain:
            host = p.ip_address.subdomain.subdomain

        if _probe_http(host, port_num, "https"):
            service = "https"
            is_web = True
        elif _probe_http(host, port_num, "http"):
            service = "http"
            is_web = True
        else:
            service = ""
            is_web = False

        if service or is_web != p.is_web:
            Port.objects.filter(id=p.id).update(service=service, is_web=is_web)
            updated += 1
            logger.debug(
                f"[service_detection:{session.id}] {host}:{port_num} → "
                f"{service if service else 'non-web'} (web={is_web})"
            )

    logger.info(f"[service_detection:{session.id}] {updated}/{len(open_ports)} ports classified")
    return updated
