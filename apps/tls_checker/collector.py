"""TLS Checker — probes all open ports for encryption status and configuration.

Checks based on:
  - TLS Hardening Guide (cybersecify.com/blog/tls-hardening-guide)
  - TLS Attacks & Vulnerabilities (cybersecify.com/blog/tls-attacks-and-vulnerabilities)
  - TLS 1.3 Modern Standard (cybersecify.com/blog/tls-1-3-modern-standard)
  - TLS 1.2 Deep Dive (cybersecify.com/blog/tls-1-2-deep-dive)
  - MITM Attacks Detection (cybersecify.com/blog/mitm-attacks-detection-prevention)
  - Cryptography Fundamentals (cybersecify.com/blog/cryptography-fundamentals)

Web ports: determined from httpx URL scheme (scheme only, no probing).
Non-web ports: probed via Python stdlib ssl/smtplib/imaplib/poplib/ftplib.
Inherently insecure protocols (Telnet, rsh, etc.) always flagged without probing.
HTTPS ports are also probed for the Strict-Transport-Security (HSTS) header.
"""

import datetime
import ftplib
import http.client
import imaplib
import logging
import poplib
import smtplib
import socket
import ssl

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 5  # seconds per port

# Services that use STARTTLS — must negotiate TLS after plaintext greeting
_STARTTLS_SERVICES = frozenset({"smtp", "submission", "imap", "pop3", "ftp"})

# Services that support TLS (STARTTLS or direct) but may run without it
TLS_CAPABLE_SERVICES = frozenset({
    "smtp", "submission", "imap", "pop3", "ftp", "ldap",
    "mysql", "postgresql", "ms-sql-s", "mongodb",
    "redis", "rdp", "ms-wbt-server", "vnc",
    "memcached", "couchdb", "elasticsearch", "amqp",
})

# Services with no TLS standard — always an unencrypted finding
INHERENTLY_INSECURE_SERVICES = frozenset({
    "telnet", "rlogin", "rsh", "rexec",
})

# Legacy TLS versions to probe (may not be available on all OpenSSL builds)
_LEGACY_TLS_VERSIONS: list[tuple] = []
for _attr, _key in [("TLSv1", "tls10"), ("TLSv1_1", "tls11")]:
    if hasattr(ssl.TLSVersion, _attr):
        _LEGACY_TLS_VERSIONS.append((getattr(ssl.TLSVersion, _attr), _key))


# ---------------------------------------------------------------------------
# STARTTLS probers (stdlib only)
# ---------------------------------------------------------------------------

def _probe_starttls_smtp(ip: str, port: int) -> bool:
    try:
        with smtplib.SMTP(host=ip, port=port, timeout=PROBE_TIMEOUT) as s:
            s.starttls()
            return True
    except Exception:
        return False


def _probe_starttls_imap(ip: str, port: int) -> bool:
    try:
        m = imaplib.IMAP4(host=ip, port=port, timeout=PROBE_TIMEOUT)
        m.starttls()
        m.logout()
        return True
    except Exception:
        return False


def _probe_starttls_pop3(ip: str, port: int) -> bool:
    try:
        m = poplib.POP3(host=ip, port=port, timeout=PROBE_TIMEOUT)
        m.stls()
        m.quit()
        return True
    except Exception:
        return False


def _probe_starttls_ftp(ip: str, port: int) -> bool:
    try:
        ftp = ftplib.FTP_TLS()
        ftp.connect(host=ip, port=port, timeout=PROBE_TIMEOUT)
        ftp.auth()
        ftp.quit()
        return True
    except Exception:
        return False


_STARTTLS_PROBERS = {
    "smtp":       _probe_starttls_smtp,
    "submission": _probe_starttls_smtp,
    "imap":       _probe_starttls_imap,
    "pop3":       _probe_starttls_pop3,
    "ftp":        _probe_starttls_ftp,
}


# ---------------------------------------------------------------------------
# TLS detail probing
# ---------------------------------------------------------------------------

def _tls_context() -> ssl.SSLContext:
    """Base context: no hostname/cert validation (we probe presence + config)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _check_hsts(ip: str, port: int, host: str) -> str | None:
    """
    Make an HTTPS HEAD request and return the Strict-Transport-Security header value.

    Returns None if HSTS is absent or if the connection fails.
    Uses the provided host for the HTTP Host header (supports virtual hosting / CDN).
    """
    try:
        conn = http.client.HTTPSConnection(
            ip, port, timeout=PROBE_TIMEOUT, context=_tls_context()
        )
        conn.request("HEAD", "/", headers={"Host": host, "User-Agent": "openeasd-tls-checker/1.0"})
        resp = conn.getresponse()
        return resp.getheader("Strict-Transport-Security")
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _probe_tls_details(ip: str, port: int) -> dict | None:
    """
    Connect via TLS and collect protocol version, cipher suite, and cert info.
    Returns None if TLS is not available on this port.

    Result dict:
      tls_version      — "TLSv1.3" / "TLSv1.2" / etc.
      cipher_name      — OpenSSL cipher name e.g. "ECDHE-RSA-AES256-GCM-SHA384"
      cipher_bits      — key size in bits
      cert_expiry_days — days until cert expiry (None if unavailable)
      cert_self_signed — True if issuer == subject
    """
    try:
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as sock:
            with _tls_context().wrap_socket(sock, server_hostname=ip) as ssock:
                version = ssock.version() or ""
                cipher_name, _, cipher_bits = ssock.cipher() or ("", "", 0)
                cert = ssock.getpeercert() or {}
                return {
                    "tls_version":      version,
                    "cipher_name":      cipher_name or "",
                    "cipher_bits":      cipher_bits or 0,
                    "cert_expiry_days": _cert_days_remaining(cert),
                    "cert_self_signed": _is_self_signed(cert),
                }
    except Exception:
        return None


def _cert_days_remaining(cert: dict) -> int | None:
    """Days until certificate expiry from getpeercert() dict."""
    expiry_str = cert.get("notAfter")
    if not expiry_str:
        return None
    try:
        expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        return (expiry - datetime.datetime.utcnow()).days
    except ValueError:
        return None


def _is_self_signed(cert: dict) -> bool:
    """Certificate is self-signed when issuer equals subject."""
    if not cert:
        return False
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    return bool(subject) and subject == issuer


def _check_legacy_protocol_support(ip: str, port: int) -> dict:
    """
    Probe whether the server accepts deprecated TLS 1.0 or TLS 1.1.
    Per RFC 8996 both are deprecated. TLS 1.0 is also vulnerable to BEAST.

    Returns {"tls10": bool, "tls11": bool}.
    Note: if the system OpenSSL has these disabled, checks always return False.
    """
    results: dict[str, bool] = {"tls10": False, "tls11": False}
    for tls_version, key in _LEGACY_TLS_VERSIONS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip):
                    results[key] = True
        except Exception:
            pass
    return results


def _probe_tls(ip: str, port: int, service: str) -> dict | None:
    """
    Probe TLS for a non-web port. Returns TLS details dict if TLS is available,
    None if no TLS (or STARTTLS + direct TLS both fail).

    For STARTTLS services: tries STARTTLS first, falls back to direct TLS
    (handles implicit TLS on non-standard ports e.g. smtps on 465).
    """
    if service in _STARTTLS_PROBERS:
        # Try STARTTLS — if it works, do a full detail probe via direct TLS
        # (STARTTLS details aren't easily extractable from smtplib/imaplib)
        starttls_ok = _STARTTLS_PROBERS[service](ip, port)
        details = _probe_tls_details(ip, port)
        if details:
            return details  # Direct TLS also works (implicit TLS port)
        if starttls_ok:
            # STARTTLS works but direct TLS doesn't — return minimal detail dict
            return {
                "tls_version":      "",   # can't determine without direct handshake
                "cipher_name":      "",
                "cipher_bits":      0,
                "cert_expiry_days": None,
                "cert_self_signed": False,
            }
        return None
    return _probe_tls_details(ip, port)


# ---------------------------------------------------------------------------
# Main collection function
# ---------------------------------------------------------------------------

def collect(session) -> list[dict]:
    """
    Probe all open ports for TLS status and configuration.

    Returns one result dict per port that requires TLS analysis:
      {
        ip, port, service,
        has_tls:           bool,
        is_web:            bool,
        scheme:            str | None,       # "http"/"https" for web ports
        inherently_insecure: bool,
        port_fk, url_fk,
        # populated when has_tls=True:
        tls_version:       str,              # "TLSv1.3", "TLSv1.2", ""
        cipher_name:       str,              # OpenSSL cipher name
        cipher_bits:       int,
        cert_expiry_days:  int | None,
        cert_self_signed:  bool,
        supports_tls10:    bool,
        supports_tls11:    bool,
        hsts_header:       str | None,       # Strict-Transport-Security value (HTTPS web ports only)
      }

    Ports with unknown services (not in TLS_CAPABLE or INHERENTLY_INSECURE)
    that are not web ports are omitted — no findings can be generated.
    """
    from apps.core.assets.models import Port, URL

    open_ports = list(Port.objects.filter(session=session, state="open"))
    if not open_ports:
        return []

    # Build (host, port_number) → (scheme, URL obj) from httpx phase
    web_port_map: dict[tuple[str, int], tuple[str, object]] = {}
    for url in URL.objects.filter(session=session):
        if url.host and url.port_number:
            web_port_map[(url.host, url.port_number)] = (url.scheme, url)

    _tls_empty = {
        "tls_version": "", "cipher_name": "", "cipher_bits": 0,
        "cert_expiry_days": None, "cert_self_signed": False,
        "supports_tls10": False, "supports_tls11": False,
        "hsts_header": None,
    }

    results = []
    for p in open_ports:
        ip = p.address
        port_num = p.port
        service = (p.service or "").lower()
        web_entry = web_port_map.get((ip, port_num))

        if web_entry is not None:
            scheme, url_obj = web_entry
            has_tls = scheme == "https"
            tls_detail: dict = _tls_empty.copy()

            if has_tls:
                details = _probe_tls_details(ip, port_num)
                if details:
                    legacy = _check_legacy_protocol_support(ip, port_num)
                    tls_detail = {**details, **legacy}
                else:
                    tls_detail = {**_tls_empty, "supports_tls10": False, "supports_tls11": False}
                host = (url_obj.host if url_obj and url_obj.host else ip)
                tls_detail["hsts_header"] = _check_hsts(ip, port_num, host)
            else:
                tls_detail = {**_tls_empty}

            results.append({
                "ip": ip, "port": port_num, "service": service,
                "has_tls": has_tls, "is_web": True, "scheme": scheme,
                "inherently_insecure": False,
                "port_fk": p, "url_fk": url_obj,
                **tls_detail,
            })

        elif service in INHERENTLY_INSECURE_SERVICES:
            logger.debug(f"[tls_checker:{session.id}] {ip}:{port_num} inherently insecure ({service})")
            results.append({
                "ip": ip, "port": port_num, "service": service,
                "has_tls": False, "is_web": False, "scheme": None,
                "inherently_insecure": True,
                "port_fk": p, "url_fk": None,
                **_tls_empty,
            })

        elif service in TLS_CAPABLE_SERVICES:
            logger.debug(f"[tls_checker:{session.id}] Probing TLS on {ip}:{port_num} ({service})")
            details = _probe_tls(ip, port_num, service)
            has_tls = details is not None
            tls_detail = _tls_empty.copy()

            if has_tls and details:
                legacy = _check_legacy_protocol_support(ip, port_num)
                tls_detail = {**details, **legacy}

            results.append({
                "ip": ip, "port": port_num, "service": service,
                "has_tls": has_tls, "is_web": False, "scheme": None,
                "inherently_insecure": False,
                "port_fk": p, "url_fk": None,
                **tls_detail,
            })
        # else: unknown service on non-web port — skip

    encrypted = sum(1 for r in results if r["has_tls"])
    plaintext = len(results) - encrypted
    logger.info(
        f"[tls_checker:{session.id}] Checked {len(results)} ports: "
        f"{encrypted} encrypted, {plaintext} plaintext"
    )
    return results
