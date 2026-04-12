"""Service detection — pure Python probes to classify ports as web/non-web.

Probes each open port to determine the running service:
  1. HTTP probe (requests) → http/https → is_web=True
  2. Banner grab (socket) → ssh, smtp, pop3, imap, redis, ftp, etc.

No external binary dependency — uses only Python stdlib + requests.
"""

import logging
import socket
import ssl

import requests
import urllib3

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning from verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROBE_TIMEOUT = 3  # seconds per probe

# Services that indicate a web port
WEB_SERVICES = frozenset({"http", "https"})

# Banner prefix → service name (checked in order, first match wins)
_BANNER_SIGNATURES = [
    ("SSH-", "ssh"),
    ("220 ", "smtp"),          # 220 mail.example.com ESMTP
    ("220-", "smtp"),          # 220-mail.example.com multiline
    ("+OK", "pop3"),           # +OK POP3 server ready
    ("* OK", "imap"),          # * OK IMAP server ready
    ("-ERR", "redis"),         # Redis error response
    ("+PONG", "redis"),        # Redis PING response
    ("$", "redis"),            # Redis bulk string
]


def _probe_http(ip: str, port: int) -> str | None:
    """Try HTTP and HTTPS requests. Return "https", "http", or None."""
    for scheme in ("https", "http"):
        try:
            resp = requests.head(
                f"{scheme}://{ip}:{port}",
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "openeasd-service-probe/1.0"},
            )
            if resp.status_code > 0:
                return scheme
        except requests.RequestException:
            continue
    return None


def _probe_banner(ip: str, port: int) -> str | None:
    """Connect via raw socket, read banner, match against known signatures."""
    try:
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as sock:
            sock.settimeout(PROBE_TIMEOUT)
            data = sock.recv(1024)
            if not data:
                return None
            banner = data.decode("utf-8", errors="replace").strip()
            for prefix, service in _BANNER_SIGNATURES:
                if banner.startswith(prefix):
                    return service
    except Exception:
        pass
    return None


def _probe_tls(ip: str, port: int) -> bool:
    """Check if the port speaks TLS (direct handshake). Returns True if TLS."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip):
                return True
    except Exception:
        return False


def detect_services(session) -> int:
    """
    Probe all open ports to identify services. Updates Port.service and
    Port.is_web. Returns count of ports updated.

    Probe order per port:
      1. HTTP probe (requests HEAD on https:// then http://)
      2. Banner grab (raw socket, match known signatures)
      3. If no match and TLS handshake succeeds → "https"
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
        service = None

        # Step 1: HTTP probe
        http_result = _probe_http(ip, port_num)
        if http_result:
            service = http_result
        else:
            # Step 2: Banner grab
            service = _probe_banner(ip, port_num)

            # Step 3: TLS fallback — if no banner but TLS works, likely HTTPS
            if not service and _probe_tls(ip, port_num):
                service = "https"

        if service:
            is_web = service in WEB_SERVICES
            Port.objects.filter(id=p.id).update(service=service, is_web=is_web)
            updated += 1
            logger.debug(
                f"[service_detection:{session.id}] {ip}:{port_num} → {service} (web={is_web})"
            )

    logger.info(f"[service_detection:{session.id}] Updated {updated}/{len(open_ports)} ports")
    return updated
