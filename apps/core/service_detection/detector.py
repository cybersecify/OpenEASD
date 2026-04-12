"""Service detection — classifies ports as web or non-web.

Probing strategy (in order of preference):
  1. HTTPS request with subdomain hostname  (CDN/SNI compatible)
  2. HTTP  request with subdomain hostname
  3. HTTPS request with raw IP              (handles CDN SNI rejection)
  4. HTTP  request with raw IP
  5. nmap -sV fallback for any still-unresolved ports — accurate service
     fingerprinting; one nmap call per IP, all unresolved ports batched.

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

# Ports that are almost exclusively used for web traffic.
# When nmap returns "tcpwrapped" (firewall intercepts before service responds)
# on these ports we treat them as web rather than silently dropping them —
# the cost of a false positive here is low, but missing them means nuclei /
# web_checker / httpx never scan them.
_WEB_ONLY_PORTS = frozenset({80, 443, 8080, 8443})


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

    # ── Phase 1: HTTP probing ─────────────────────────────────────────────
    results: dict[int, tuple[str, bool]] = {}  # port.id → (service, is_web)
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
            # Retry with raw IP — handles CDN SNI rejection
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

    # ── Phase 2: nmap -sV fallback for unresolved ports ──────────────────
    if unresolved:
        # Group unresolved ports by IP for batched nmap calls
        by_ip: dict[str, list] = {}
        for p in unresolved:
            by_ip.setdefault(p.address, []).append(p)

        for ip, ports in by_ip.items():
            port_nums = [p.port for p in ports]
            nmap_services = _nmap_sv(ip, port_nums)

            for p in ports:
                nmap_svc = nmap_services.get(p.port, "")
                is_web   = nmap_svc in _NMAP_WEB_SERVICES

                # Last-resort: tcpwrapped or ssl/unknown on a well-known web port.
                # - tcpwrapped: firewall intercepted before the service responded.
                # - ssl/unknown: nmap completed TLS but couldn't identify the app
                #   (client-cert required, strict WAF, some load balancers).
                # Treat as web so httpx/nuclei/web_checker still pick it up.
                if not is_web and nmap_svc in {"tcpwrapped", "ssl/unknown"} and p.port in _WEB_ONLY_PORTS:
                    is_web  = True
                    nmap_svc = "https" if p.port in {443, 8443} else "http"
                    logger.debug(
                        f"[service_detection:{session.id}] {ip}:{p.port} — "
                        f"tcpwrapped on well-known web port, assuming {nmap_svc}"
                    )

                service = nmap_svc
                results[p.id] = (service, is_web)
                logger.debug(
                    f"[service_detection:{session.id}] {ip}:{p.port} → "
                    f"{service or 'unknown'} (nmap fallback, web={is_web})"
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
        f"({len(unresolved)} via nmap fallback)"
    )
    return updated
