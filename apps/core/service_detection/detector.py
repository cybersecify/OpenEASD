"""Service detection — classifies ports as web or non-web using confidence scoring.

Classification strategy (highest signal first):

  Step 1 — Banner grab (all ports, cheapest signal)
    Raw TCP read: SSH/FTP/SMTP banner → score −70, skip HTTP probing
                  HTTP banner → score +70, run 1 HTTP probe to confirm
                  Empty/unknown → proceed to HTTP probing

  Step 2 — HTTP probing (skipped when banner strongly non-web)
    HTTPS + hostname (score +80), HTTP + hostname (score +80)
    HTTPS + raw IP (score +60), HTTP + raw IP (score +60)
    Stops at first success.

  Step 3 — nmap -sV for still-unresolved ports
    Batched per (IP, hostname). Known web → +70, known non-web → −80.
    tcpwrapped → 0 (no information). ssl/unknown → +40 (known web port) or +10.

  Step 4 — Well-known port hint (always applied)
    80, 443, 8080, 8443 → +20

Final: score >= CLASSIFICATION_THRESHOLD (50) → is_web=True

Primary output:  Port.is_web (True/False)
Secondary output: Port.service (e.g. "https", "http", "ssh", ...)
"""

import logging
import socket
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

CLASSIFICATION_THRESHOLD = 50

# nmap service names that identify clearly non-web services.
_NMAP_NON_WEB_SERVICES = frozenset({
    "ssh", "ftp", "ftps", "smtp", "smtps", "imap", "imaps",
    "pop3", "pop3s", "telnet", "rdp", "ms-wbt-server",
    "mysql", "postgresql", "ms-sql-s", "oracle", "mongodb",
    "redis", "memcached", "ldap", "ldaps", "snmp", "ntp",
    "sip", "sips", "dns", "domain", "rpcbind", "sunrpc",
    "netbios-ssn", "microsoft-ds",
})

# Banner prefixes/substrings that identify clearly non-web services.
_BANNER_NON_WEB_SIGNALS = ("SSH-2.0-", "SSH-1.", "220 ", "EHLO", "ESMTP", "+OK ", "* OK ", "* BYE")

# Banner substrings that identify web services.
_BANNER_WEB_SIGNALS = ("HTTP/", "<!DOCTYPE", "<html")


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
# Banner grabbing
# ---------------------------------------------------------------------------

BANNER_TIMEOUT = 3
BANNER_READ_BYTES = 512


def _grab_banner(host: str, port: int) -> str:
    """
    Open a raw TCP connection and read the first bytes the server sends.

    Returns the decoded banner string, or "" on any failure (timeout,
    refused, no data). Used to detect SSH/FTP/SMTP before wasting HTTP
    probe attempts on them.
    """
    try:
        with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as sock:
            data = sock.recv(BANNER_READ_BYTES)
            return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _banner_score(banner: str) -> int:
    """
    Score a raw TCP banner.

    Returns +70 for HTTP banners, -70 for SSH/FTP/SMTP banners, 0 otherwise.
    """
    if not banner:
        return 0
    for signal in _BANNER_WEB_SIGNALS:
        if signal in banner:
            return 70
    for signal in _BANNER_NON_WEB_SIGNALS:
        if signal in banner:
            return -70
    return 0


def _nmap_score(nmap_svc: str, port_num: int) -> int:
    """
    Score an nmap service name.

    ssl/unknown on a known web port scores higher to preserve CDN/CloudFront
    detection (those services block most probes but nmap still sees ssl/unknown).
    tcpwrapped contributes nothing — it carries no protocol information.
    """
    if not nmap_svc:
        return 0
    if nmap_svc in _NMAP_WEB_SERVICES:
        return 70
    if nmap_svc in _NMAP_NON_WEB_SERVICES:
        return -80
    if nmap_svc == "ssl/unknown":
        return 40 if port_num in _KNOWN_WEB_PORTS else 10
    if nmap_svc == "tcpwrapped":
        return 0  # no protocol information — intentionally neutral (was a false-positive source)
    return 0


def _port_hint_score(port_num: int) -> int:
    """
    Weak bonus for well-known web port numbers.

    Not enough alone to cross CLASSIFICATION_THRESHOLD — requires at least
    one other positive signal.
    """
    return 20 if port_num in _KNOWN_WEB_PORTS else 0


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


def _nmap_sv(ip: str, ports: list[int], hostname: str | None = None) -> dict[int, str]:
    """
    Run ``nmap -sV`` on the given IP for the specified ports.

    When a hostname is provided (and differs from the IP), nmap uses it as
    the scan target so it appears in TLS SNI during version probes — critical
    for CDN/virtual-hosted services that reject connections without a valid
    SNI name.  ``-Pn`` skips host discovery so nmap scans the resolved IP
    even if ICMP is blocked.

    Returns {port_num: service_name} — empty dict on any failure.
    """
    binary  = getattr(settings, "TOOL_NMAP", "/opt/homebrew/bin/nmap")
    port_str = ",".join(str(p) for p in sorted(ports))
    # Use hostname as scan target when available so nmap sets SNI correctly.
    target  = hostname if hostname and hostname != ip else ip
    cmd = [
        binary,
        "-sV", "--version-intensity", "2",
        "-Pn",           # skip host discovery — we know the host is up
        "-p", port_str,
        "--open",
        "-oX", "-",      # XML to stdout
        "--host-timeout", "30s",
        target,
    ]
    logger.debug(f"[service_detection] nmap: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT
        )
        if result.returncode not in (0, 1):
            logger.debug(
                f"[service_detection] nmap exited {result.returncode} for {target}: "
                f"{result.stderr[:200]}"
            )
        return _parse_nmap_sv_xml(result.stdout)
    except FileNotFoundError:
        logger.warning(f"[service_detection] nmap binary not found: {binary}")
    except subprocess.TimeoutExpired:
        logger.warning(f"[service_detection] nmap timed out for {target}:{port_str}")
    except Exception as e:
        logger.warning(f"[service_detection] nmap error for {target}: {e}")
    return {}


# ---------------------------------------------------------------------------
# Main detection entry point
# ---------------------------------------------------------------------------

def detect_services(session) -> int:
    """
    Classify all open ports as web or non-web using confidence scoring.

    Each port accumulates a score from independent signals:
      banner grab → +70 (HTTP) or −70 (SSH/FTP/SMTP)
      HTTP probe  → +80 (hostname) or +60 (IP fallback)
      nmap -sV    → +70 (web service) or −80 (non-web service)
      port hint   → +20 for 80/443/8080/8443

    score >= CLASSIFICATION_THRESHOLD (50) → is_web=True

    Returns the count of ports whose service or is_web changed.
    """
    from apps.core.assets.models import Port

    open_ports = list(
        Port.objects.filter(session=session, state="open")
        .select_related("ip_address__subdomain")
    )
    if not open_ports:
        logger.info(f"[service_detection:{session.id}] No open ports")
        return 0

    scores: dict[int, int] = {}         # port.id → accumulated score
    http_services: dict[int, str] = {}  # port.id → service name from HTTP probe
    nmap_results: dict[int, str] = {}   # port.id → service name from nmap
    needs_nmap: list = []

    # ── Steps 1+2: Banner grab then HTTP probing ──────────────────────────────
    for p in open_ports:
        ip       = p.address
        port_num = p.port
        hostname = ip
        if p.ip_address and p.ip_address.subdomain:
            hostname = p.ip_address.subdomain.subdomain

        # Step 1: banner grab — cheapest signal, runs first
        banner  = _grab_banner(hostname, port_num)
        b_score = _banner_score(banner)
        score   = b_score

        # Step 2: HTTP probing — skip when banner is clearly non-web (saves 4 probes)
        http_svc = ""
        if b_score >= -50:
            if _probe_http(hostname, port_num, "https"):
                score += 80
                http_svc = "https"
            elif _probe_http(hostname, port_num, "http"):
                score += 80
                http_svc = "http"
            elif hostname != ip:
                if _probe_http(ip, port_num, "https"):
                    score += 60
                    http_svc = "https"
                elif _probe_http(ip, port_num, "http"):
                    score += 60
                    http_svc = "http"

        # Step 4: port hint — always applied
        score += _port_hint_score(port_num)

        scores[p.id]        = score
        http_services[p.id] = http_svc

        logger.debug(
            f"[service_detection:{session.id}] {hostname}:{port_num} "
            f"banner_score={b_score} http_svc={http_svc!r} score_so_far={score}"
        )

        if not http_svc:
            needs_nmap.append(p)

    # ── Step 3: nmap -sV — only for ports not resolved by HTTP ───────────────
    if needs_nmap:
        by_target: dict[tuple[str, str], list] = {}
        for p in needs_nmap:
            hostname = p.address
            if p.ip_address and p.ip_address.subdomain:
                hostname = p.ip_address.subdomain.subdomain
            by_target.setdefault((p.address, hostname), []).append(p)

        for (ip, hostname), ports in by_target.items():
            nmap_services = _nmap_sv(ip, [p.port for p in ports], hostname=hostname)
            for p in ports:
                nmap_svc = nmap_services.get(p.port, "")
                nmap_results[p.id] = nmap_svc
                n_score = _nmap_score(nmap_svc, p.port)
                scores[p.id] += n_score
                logger.debug(
                    f"[service_detection:{session.id}] {hostname}:{p.port} "
                    f"nmap={nmap_svc!r} nmap_score={n_score} total={scores[p.id]}"
                )

    # ── Persist ───────────────────────────────────────────────────────────────
    updated = 0
    for p in open_ports:
        score  = scores[p.id]
        is_web = score >= CLASSIFICATION_THRESHOLD

        # Determine service name: HTTP probe wins, then nmap, then port default
        service = http_services.get(p.id, "") or nmap_results.get(p.id, "")
        # Sanitise ambiguous nmap names: if classified web but name is uninformative,
        # use the port-based default
        if is_web and service in {"ssl/unknown", "tcpwrapped", ""}:
            service = _KNOWN_WEB_PORTS.get(p.port, "https" if p.port in {443, 8443} else "http")

        logger.info(
            f"[service_detection:{session.id}] {p.address}:{p.port} "
            f"score={score} → {'web' if is_web else 'non-web'} service={service!r}"
        )

        if service != p.service or is_web != p.is_web:
            Port.objects.filter(id=p.id).update(service=service, is_web=is_web)
            updated += 1

    logger.info(
        f"[service_detection:{session.id}] {updated}/{len(open_ports)} ports classified"
    )
    return updated
