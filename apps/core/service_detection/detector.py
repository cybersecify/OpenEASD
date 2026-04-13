"""Service detection — classifies ports as web or non-web.

Classification strategy (most accurate first, fallback last):

  Step 1 — HTTP probing (all ports)
    1a. HTTPS + subdomain hostname  (CDN/SNI compatible)
    1b. HTTP  + subdomain hostname
    1c. HTTPS + raw IP              (CDN SNI rejection fallback)
    1d. HTTP  + raw IP

  Step 2 — nmap -sV for still-unresolved ports
    Batched per IP; accurately fingerprints ssh/ftp/smtp/https etc.
    Treats tcpwrapped / ssl/unknown on known-web ports as web.

  Step 3 — Well-known port fallback (last resort)
    80, 8080  → http  (web)
    443, 8443 → https (web)
    Only applied when both probing and nmap fail to classify the port
    (e.g. CloudFront blocking all probes on port 443).

Primary output:  Port.is_web (True/False)
Secondary output: Port.service (e.g. "https", "http", "ssh", ...)
"""

import logging
import subprocess

import defusedxml.ElementTree as ET
import requests
import urllib3
from django.conf import settings

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROBE_TIMEOUT = 3
NMAP_TIMEOUT  = 60  # seconds for the nmap subprocess

WEB_SERVICES = frozenset({"http", "https"})

# nmap service names that mean "this is a web port".
# Includes ssl/* variants that nmap emits when it detects TLS but resolves the
# underlying protocol — e.g. "ssl/http", "ssl/https".
_NMAP_WEB_SERVICES = frozenset({
    "http", "https",
    "http-alt", "https-alt",
    "http-proxy", "http-mgmt",
    "webcache", "http-rpc-epmap",
    "ssl/http", "ssl/https",
    "ipp",           # CUPS / IPP — HTTP-based
})

# Well-known web ports — classified deterministically by port number in Step 1.
# port → default service name
_KNOWN_WEB_PORTS: dict[int, str] = {
    80:   "http",
    443:  "https",
    8080: "http",
    8443: "https",
}


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------

def _probe_http(host: str, port: int, scheme: str) -> bool:
    """Try an HTTP HEAD request. Returns True if the server responds."""
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


# ---------------------------------------------------------------------------
# nmap -sV fallback
# ---------------------------------------------------------------------------

def _parse_nmap_sv_xml(xml_str: str) -> dict[int, str]:
    """
    Parse nmap -sV XML output and return {port_num: service_name}.

    Normalises tunnel="ssl" + name="http" → "https" so callers can check
    against _NMAP_WEB_SERVICES without special-casing the tunnel attribute.
    """
    services: dict[int, str] = {}
    if not xml_str:
        return services
    try:
        root = ET.fromstring(xml_str)
        for port_el in root.findall(".//port"):
            portid = port_el.get("portid", "")
            if not portid.isdigit():
                continue
            service_el = port_el.find("service")
            if service_el is None:
                continue
            name   = service_el.get("name",   "").lower()
            tunnel = service_el.get("tunnel", "").lower()
            # nmap reports TLS-wrapped services as tunnel="ssl" + name=<protocol>.
            # Normalise to "ssl/<name>" so callers can match against _NMAP_WEB_SERVICES
            # without special-casing the tunnel attribute (e.g. ssl/http, ssl/https).
            if tunnel == "ssl" and not name.startswith("ssl/"):
                name = f"ssl/{name}"
            services[int(portid)] = name
    except ET.ParseError as e:
        logger.warning(f"[service_detection] nmap XML parse error: {e}")
    except Exception as e:
        logger.debug(f"[service_detection] nmap XML parse unexpected error: {e}")
    return services


def _nmap_sv(ip: str, ports: list[int]) -> dict[int, str]:
    """
    Run ``nmap -sV`` on the given IP for the specified ports.
    Returns {port_num: service_name} — empty dict on any failure.
    """
    binary = getattr(settings, "TOOL_NMAP", "/opt/homebrew/bin/nmap")
    port_str = ",".join(str(p) for p in sorted(ports))
    cmd = [
        binary,
        "-sV", "--version-intensity", "2",  # balanced: covers most services without being slow
        "-p", port_str,
        "--open",
        "-oX", "-",   # XML to stdout
        "--host-timeout", "30s",
        ip,
    ]
    logger.debug(f"[service_detection] nmap fallback: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT
        )
        if result.returncode not in (0, 1):  # 1 = no hosts up (still valid XML)
            logger.debug(
                f"[service_detection] nmap exited {result.returncode} for {ip}: "
                f"{result.stderr[:200]}"
            )
        return _parse_nmap_sv_xml(result.stdout)
    except FileNotFoundError:
        logger.warning(f"[service_detection] nmap binary not found: {binary}")
    except subprocess.TimeoutExpired:
        logger.warning(f"[service_detection] nmap timed out for {ip}:{port_str}")
    except Exception as e:
        logger.warning(f"[service_detection] nmap error for {ip}: {e}")
    return {}


# ---------------------------------------------------------------------------
# Main detection entry point
# ---------------------------------------------------------------------------

def detect_services(session) -> int:
    """
    Classify all open ports as web or non-web and set Port.service.

    Returns the count of ports updated in the database.
    """
    from apps.core.assets.models import Port

    open_ports = list(
        Port.objects.filter(session=session, state="open")
        .select_related("ip_address__subdomain")
    )
    if not open_ports:
        logger.info(f"[service_detection:{session.id}] No open ports")
        return 0

    results: dict[int, tuple[str, bool]] = {}  # port.id → (service, is_web)

    # ── Step 1: HTTP probing (all ports) ──────────────────────────────────
    unresolved: list = []
    for p in open_ports:
        ip       = p.address
        port_num = p.port
        hostname = ip
        if p.ip_address and p.ip_address.subdomain:
            hostname = p.ip_address.subdomain.subdomain

        service, is_web = "", False

        if _probe_http(hostname, port_num, "https"):
            service, is_web = "https", True
        elif _probe_http(hostname, port_num, "http"):
            service, is_web = "http", True
        elif hostname != ip:
            if _probe_http(ip, port_num, "https"):
                service, is_web = "https", True
            elif _probe_http(ip, port_num, "http"):
                service, is_web = "http", True

        if is_web:
            results[p.id] = (service, is_web)
            logger.debug(
                f"[service_detection:{session.id}] {hostname}:{port_num} → "
                f"{service} (http probe)"
            )
        else:
            unresolved.append(p)

    # ── Step 2: nmap -sV for still-unresolved ports ───────────────────────
    still_unresolved: list = []
    if unresolved:
        by_ip: dict[str, list] = {}
        for p in unresolved:
            by_ip.setdefault(p.address, []).append(p)

        for ip, ports in by_ip.items():
            nmap_services = _nmap_sv(ip, [p.port for p in ports])

            for p in ports:
                nmap_svc = nmap_services.get(p.port, "")
                is_web   = nmap_svc in _NMAP_WEB_SERVICES

                if not is_web and nmap_svc in {"tcpwrapped", "ssl/unknown"}:
                    is_web   = True
                    nmap_svc = "https" if p.port in {443, 8443} else "http"
                    logger.debug(
                        f"[service_detection:{session.id}] {ip}:{p.port} — "
                        f"nmap={nmap_svc!r}, assuming {nmap_svc}"
                    )

                if is_web or nmap_svc:
                    results[p.id] = (nmap_svc, is_web)
                    logger.debug(
                        f"[service_detection:{session.id}] {ip}:{p.port} → "
                        f"{nmap_svc or 'unknown'} (nmap, web={is_web})"
                    )
                else:
                    still_unresolved.append(p)

    # ── Step 3: well-known port fallback (last resort) ────────────────────
    for p in still_unresolved:
        if p.port in _KNOWN_WEB_PORTS:
            service = _KNOWN_WEB_PORTS[p.port]
            results[p.id] = (service, True)
            logger.debug(
                f"[service_detection:{session.id}] {p.address}:{p.port} → "
                f"{service} (well-known port fallback)"
            )

    # ── Persist ───────────────────────────────────────────────────────────
    updated = 0
    for p in open_ports:
        service, is_web = results.get(p.id, ("", False))
        if service != p.service or is_web != p.is_web:
            Port.objects.filter(id=p.id).update(service=service, is_web=is_web)
            updated += 1

    logger.info(
        f"[service_detection:{session.id}] {updated}/{len(open_ports)} ports classified "
        f"({len(unresolved)} to nmap, {len(still_unresolved)} to well-known fallback)"
    )
    return updated
