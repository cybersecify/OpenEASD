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

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
from cryptography.hazmat.primitives.hashes import SHA1

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


def _parse_cert_details(der_bytes: bytes, hostname: str | None = None) -> dict:
    """
    Parse DER-encoded certificate bytes via ``cryptography`` and return a dict
    of certificate metadata.  Returns safe defaults on any parsing error.

    Fields returned:
      cert_expiry_days   — int (days until expiry, negative = expired)
      cert_self_signed   — bool (issuer == subject)
      cert_key_type      — "RSA" | "EC" | "DSA" | "unknown"
      cert_key_bits      — int (key size in bits)
      cert_sig_algorithm — str (OID name, e.g. "sha256WithRSAEncryption")
      cert_sig_sha1      — bool (True if signature uses SHA-1)
      cert_san_list      — list[str] (DNS names from SAN extension)
      cert_san_mismatch  — bool (hostname not in SAN list)
      cert_has_sct       — bool (SCT extension present)
    """
    defaults: dict = {
        "cert_expiry_days": None, "cert_self_signed": False,
        "cert_key_type": None, "cert_key_bits": None,
        "cert_sig_algorithm": None, "cert_sig_sha1": False,
        "cert_san_list": [], "cert_san_mismatch": False,
        "cert_has_sct": False,
    }
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return defaults

    result = dict(defaults)

    # ── Expiry ───────────────────────────────────────────────────────────
    try:
        expiry = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        result["cert_expiry_days"] = (expiry - now).days
    except Exception:
        pass

    # ── Self-signed ──────────────────────────────────────────────────────
    try:
        result["cert_self_signed"] = cert.issuer == cert.subject
    except Exception:
        pass

    # ── Key type & size ──────────────────────────────────────────────────
    try:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            result["cert_key_type"] = "RSA"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            result["cert_key_type"] = "EC"
        elif isinstance(pub, dsa.DSAPublicKey):
            result["cert_key_type"] = "DSA"
        else:
            result["cert_key_type"] = "unknown"
        result["cert_key_bits"] = pub.key_size
    except Exception:
        pass

    # ── Signature algorithm ──────────────────────────────────────────────
    try:
        result["cert_sig_algorithm"] = cert.signature_algorithm_oid._name
        result["cert_sig_sha1"] = isinstance(cert.signature_hash_algorithm, SHA1)
    except Exception:
        pass

    # ── Subject Alternative Names ────────────────────────────────────────
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
        result["cert_san_list"] = san_list
        if hostname and not _is_ip_address(hostname):
            result["cert_san_mismatch"] = not _hostname_matches_san(hostname, san_list)
    except x509.ExtensionNotFound:
        # No SAN extension — mismatch only if hostname given
        if hostname and not _is_ip_address(hostname):
            result["cert_san_mismatch"] = True
    except Exception:
        pass

    # ── Certificate Transparency (SCT) ───────────────────────────────────
    try:
        cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        )
        result["cert_has_sct"] = True
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    return result


def _is_ip_address(hostname: str) -> bool:
    """True if hostname looks like an IP address (v4 or v6)."""
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _hostname_matches_san(hostname: str, san_list: list[str]) -> bool:
    """Check if hostname matches any SAN entry (supports wildcard certs)."""
    hostname = hostname.lower()
    for san in san_list:
        san = san.lower()
        if san == hostname:
            return True
        # Wildcard match: *.example.com matches sub.example.com but not example.com
        if san.startswith("*."):
            wildcard_base = san[2:]
            if hostname.endswith(wildcard_base) and hostname.count(".") == san.count("."):
                return True
    return False


def _check_trusted_ca(ip: str, port: int, hostname: str | None = None) -> bool:
    """
    Attempt a TLS connection with full certificate validation (system trust store).
    Returns True if the certificate chain is trusted, False otherwise.
    """
    try:
        ctx = ssl.create_default_context()  # default: CERT_REQUIRED + system CA bundle
        server_hostname = hostname or ip
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname):
                return True
    except Exception:
        return False


def _probe_tls_details(ip: str, port: int, hostname: str | None = None) -> dict | None:
    """
    Connect via TLS and collect protocol version, cipher suite, and cert info.
    Returns None if TLS is not available on this port.

    Uses ``getpeercert(binary_form=True)`` + ``cryptography`` for cert parsing
    (``getpeercert()`` returns an empty dict under CERT_NONE).
    Also performs a separate validated connection to check CA trust.
    """
    try:
        with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT) as sock:
            with _tls_context().wrap_socket(sock, server_hostname=ip) as ssock:
                version = ssock.version() or ""
                cipher_name, _, cipher_bits = ssock.cipher() or ("", "", 0)
                der_bytes = ssock.getpeercert(binary_form=True)
                cert_info = _parse_cert_details(der_bytes, hostname or ip) if der_bytes else {
                    "cert_expiry_days": None, "cert_self_signed": False,
                    "cert_key_type": None, "cert_key_bits": None,
                    "cert_sig_algorithm": None, "cert_sig_sha1": False,
                    "cert_san_list": [], "cert_san_mismatch": False,
                    "cert_has_sct": False,
                }
                # Check CA trust via a separate validated connection
                cert_info["cert_trusted"] = _check_trusted_ca(ip, port, hostname)
                return {
                    "tls_version":  version,
                    "cipher_name":  cipher_name or "",
                    "cipher_bits":  cipher_bits or 0,
                    **cert_info,
                }
    except Exception:
        return None


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


def _probe_tls(ip: str, port: int, service: str, hostname: str | None = None) -> dict | None:
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
        details = _probe_tls_details(ip, port, hostname)
        if details:
            return details  # Direct TLS also works (implicit TLS port)
        if starttls_ok:
            # STARTTLS works but direct TLS doesn't — return minimal detail dict
            return {
                "tls_version": "", "cipher_name": "", "cipher_bits": 0,
                "cert_expiry_days": None, "cert_self_signed": False,
                "cert_key_type": None, "cert_key_bits": None,
                "cert_sig_algorithm": None, "cert_sig_sha1": False,
                "cert_san_list": [], "cert_san_mismatch": False,
                "cert_has_sct": False, "cert_trusted": False,
            }
        return None
    return _probe_tls_details(ip, port, hostname)


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

    # Build (IP, port_number) → (scheme, URL obj) from httpx phase.
    # URL.host is a hostname (e.g. "www.example.com") but Port.address is an IP,
    # so we join via the URL → Port FK to get the IP address for matching.
    web_port_map: dict[tuple[str, int], tuple[str, object]] = {}
    for url in URL.objects.filter(session=session).select_related("port"):
        if url.port and url.port.address and url.port.port:
            web_port_map[(url.port.address, url.port.port)] = (url.scheme, url)

    _tls_empty = {
        "tls_version": "", "cipher_name": "", "cipher_bits": 0,
        "cert_expiry_days": None, "cert_self_signed": False,
        "cert_key_type": None, "cert_key_bits": None,
        "cert_sig_algorithm": None, "cert_sig_sha1": False,
        "cert_san_list": [], "cert_san_mismatch": False,
        "cert_has_sct": False, "cert_trusted": False,
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
                host = (url_obj.host if url_obj and url_obj.host else ip)
                details = _probe_tls_details(ip, port_num, hostname=host)
                if details:
                    legacy = _check_legacy_protocol_support(ip, port_num)
                    tls_detail = {**details, **legacy}
                else:
                    tls_detail = {**_tls_empty, "supports_tls10": False, "supports_tls11": False}
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

        else:
            # Unknown or empty service — try direct TLS probe (naabu doesn't set service names)
            logger.debug(f"[tls_checker:{session.id}] Probing unknown service on {ip}:{port_num}")
            details = _probe_tls_details(ip, port_num)
            if details:
                legacy = _check_legacy_protocol_support(ip, port_num)
                tls_detail = {**details, **legacy}
                results.append({
                    "ip": ip, "port": port_num, "service": service,
                    "has_tls": True, "is_web": False, "scheme": None,
                    "inherently_insecure": False,
                    "port_fk": p, "url_fk": None,
                    **tls_detail,
                })

    encrypted = sum(1 for r in results if r["has_tls"])
    plaintext = len(results) - encrypted
    logger.info(
        f"[tls_checker:{session.id}] Checked {len(results)} ports: "
        f"{encrypted} encrypted, {plaintext} plaintext"
    )
    return results
