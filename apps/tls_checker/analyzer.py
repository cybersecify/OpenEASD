"""TLS Checker analyzer — converts probe results into Finding objects.

Finding categories based on:
  - TLS Hardening Guide      (cybersecify.com/blog/tls-hardening-guide)
  - TLS Attacks & Vulns      (cybersecify.com/blog/tls-attacks-and-vulnerabilities)
  - TLS 1.3 Modern Standard  (cybersecify.com/blog/tls-1-3-modern-standard)
  - TLS 1.2 Deep Dive        (cybersecify.com/blog/tls-1-2-deep-dive)
  - MITM Attacks Detection   (cybersecify.com/blog/mitm-attacks-detection-prevention)
  - Cryptography Fundamentals(cybersecify.com/blog/cryptography-fundamentals)
"""

import logging
import re

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cipher suite weakness detection
# ---------------------------------------------------------------------------

# Patterns matched against OpenSSL cipher name (uppercase).
# Ordered from highest to lowest severity.
_CIPHER_CHECKS: list[tuple[str, str, str, str]] = [
    # (pattern, check_type, severity, short_reason)
    (r"NULL",     "null_cipher",   "critical", "NULL cipher suite provides no encryption"),
    (r"EXPORT|^EXP-|\bEXP\b", "export_cipher", "critical", "Export-grade cipher (Logjam/FREAK attack)"),
    (r"\bRC4\b",  "rc4_cipher",   "critical", "RC4 is cryptographically broken"),
    (r"AECDH|ADH","anon_cipher",  "critical", "Anonymous cipher — no server authentication"),
    (r"3DES|DES-CBC3|BF-", "sweet32", "high",  "3DES/Blowfish Sweet32 birthday attack (64-bit block cipher)"),
    (r"\bDES\b",  "des_cipher",   "high",     "Single DES is cryptographically broken"),
    (r"\bMD5\b",  "md5_cipher",   "high",     "MD5 signature algorithm is broken"),
    (r"-SHA$",    "sha1_cipher",  "medium",   "SHA-1 HMAC in cipher suite — deprecated (SHAttered 2017)"),
    (r"\bCBC\b",  "cbc_cipher",   "medium",   "CBC mode cipher — padding oracle risk (BEAST/POODLE)"),
]

_CIPHER_TITLES = {
    "null_cipher":   "NULL cipher suite detected",
    "export_cipher": "Export-grade (EXPORT) cipher suite detected",
    "rc4_cipher":    "RC4 cipher suite detected",
    "anon_cipher":   "Anonymous cipher suite — no authentication",
    "sweet32":       "3DES cipher suite detected (Sweet32)",
    "des_cipher":    "DES cipher suite detected",
    "md5_cipher":    "MD5 signature in cipher suite",
    "sha1_cipher":   "SHA-1 HMAC cipher suite detected",
    "cbc_cipher":    "CBC mode cipher suite detected",
}

_CIPHER_REMEDIATIONS = {
    "null_cipher":   "Remove NULL cipher suites from the server configuration immediately.",
    "export_cipher": "Remove all EXPORT cipher suites. They are exploitable via Logjam and FREAK attacks.",
    "rc4_cipher":    "Remove RC4 cipher suites. RC4 is broken and banned by RFC 7465.",
    "anon_cipher":   "Remove all anonymous (ADH/AECDH) cipher suites — they allow MITM attacks.",
    "sweet32":       "Disable 3DES and Blowfish cipher suites (RFC 7525). Use AES-128-GCM or AES-256-GCM instead.",
    "des_cipher":    "Remove single-DES cipher suites and replace with AES-GCM suites.",
    "md5_cipher":    "Remove cipher suites that use MD5. Use SHA-256 or SHA-384 instead.",
    "sha1_cipher":   "Replace SHA-1 cipher suites with SHA-256 or SHA-384 variants (e.g. ECDHE-RSA-AES256-GCM-SHA384). SHA-1 was demonstrated broken by the SHAttered collision attack in 2017.",
    "cbc_cipher":    (
        "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305). "
        "If CBC is kept, ensure TLS 1.3 is primary — CBC suites are removed in TLS 1.3."
    ),
}

# RSA key exchange: cipher name starts with "RSA" but is NOT "ECDHE-RSA" or "DHE-RSA"
_RSA_KEX_PATTERN = re.compile(r"^RSA[_-]", re.IGNORECASE)


def _check_rsa_key_exchange(cipher_name: str) -> bool:
    """True if cipher uses static RSA key exchange (no forward secrecy)."""
    return bool(cipher_name) and bool(_RSA_KEX_PATTERN.match(cipher_name))


def _weak_cipher_findings(result: dict, session) -> list[Finding]:
    """Return Finding objects for any weak cipher patterns in the negotiated suite."""
    cipher_name = (result.get("cipher_name") or "").upper()
    if not cipher_name:
        return []

    ip = result["ip"]
    port_num = result["port"]
    port_fk = result["port_fk"]
    findings = []

    for pattern, check_type, severity, reason in _CIPHER_CHECKS:
        if re.search(pattern, cipher_name, re.IGNORECASE):
            findings.append(Finding(
                session=session,
                source="tls_checker",
                check_type=check_type,
                severity=severity,
                title=f"{_CIPHER_TITLES[check_type]} on {ip}:{port_num}",
                description=(
                    f"The TLS service on {ip}:{port_num} negotiated the cipher suite "
                    f"'{result['cipher_name']}'. {reason}."
                ),
                remediation=_CIPHER_REMEDIATIONS[check_type],
                port=port_fk,
                target=f"{ip}:{port_num}",
                extra={
                    "cipher_name": result["cipher_name"],
                    "cipher_bits": result.get("cipher_bits"),
                    "tls_version": result.get("tls_version"),
                    "address": ip, "port_number": port_num,
                },
            ))

    # RSA key exchange — no forward secrecy (ROBOT attack vector)
    if _check_rsa_key_exchange(result.get("cipher_name", "")):
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="no_forward_secrecy",
            severity="high",
            title=f"RSA key exchange (no forward secrecy) on {ip}:{port_num}",
            description=(
                f"The TLS service on {ip}:{port_num} uses static RSA key exchange "
                f"(cipher: '{result['cipher_name']}'). There is no forward secrecy — "
                f"if the server's private key is ever compromised, all past recorded "
                f"sessions can be decrypted. This is also the attack surface exploited "
                f"by the ROBOT vulnerability."
            ),
            remediation=(
                "Use ECDHE or DHE key exchange only. Configure server cipher preference "
                "to enforce ECDHE-based suites (e.g. ECDHE-RSA-AES256-GCM-SHA384). "
                "TLS 1.3 mandates forward secrecy by design."
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={
                "cipher_name": result["cipher_name"],
                "address": ip, "port_number": port_num,
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# Protocol version findings
# ---------------------------------------------------------------------------

def _protocol_findings(result: dict, session) -> list[Finding]:
    """Return findings for deprecated TLS protocol support."""
    ip = result["ip"]
    port_num = result["port"]
    port_fk = result["port_fk"]
    tls_version = result.get("tls_version", "")
    findings = []

    # TLS 1.0 — deprecated RFC 8996, vulnerable to BEAST
    if result.get("supports_tls10"):
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="tls10_supported",
            severity="high",
            title=f"TLS 1.0 supported on {ip}:{port_num}",
            description=(
                f"The server at {ip}:{port_num} accepts TLS 1.0 connections. "
                f"TLS 1.0 is deprecated by RFC 8996 and is vulnerable to the BEAST attack "
                f"(Browser Exploit Against SSL/TLS) when combined with CBC cipher suites. "
                f"PCI DSS and most compliance frameworks require disabling TLS 1.0."
            ),
            remediation=(
                "Disable TLS 1.0 in your server configuration. "
                "Set minimum version to TLS 1.2 (acceptable) or TLS 1.3 (recommended). "
                "Example for Nginx: ssl_protocols TLSv1.2 TLSv1.3;"
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={"address": ip, "port_number": port_num, "deprecated_version": "TLSv1"},
        ))

    # TLS 1.1 — deprecated RFC 8996
    if result.get("supports_tls11"):
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="tls11_supported",
            severity="high",
            title=f"TLS 1.1 supported on {ip}:{port_num}",
            description=(
                f"The server at {ip}:{port_num} accepts TLS 1.1 connections. "
                f"TLS 1.1 is deprecated by RFC 8996 and lacks the security improvements "
                f"of TLS 1.2. Major browsers removed TLS 1.1 support in 2020."
            ),
            remediation=(
                "Disable TLS 1.1 in your server configuration. "
                "Set minimum version to TLS 1.2 (acceptable) or TLS 1.3 (recommended). "
                "Example for Nginx: ssl_protocols TLSv1.2 TLSv1.3;"
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={"address": ip, "port_number": port_num, "deprecated_version": "TLSv1.1"},
        ))

    # TLS 1.2 only (no 1.3) — medium, not ideal
    if tls_version == "TLSv1.2" and not result.get("supports_tls10") and not result.get("supports_tls11"):
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="tls13_not_supported",
            severity="medium",
            title=f"TLS 1.3 not supported on {ip}:{port_num}",
            description=(
                f"The server at {ip}:{port_num} only negotiates up to TLS 1.2. "
                f"TLS 1.3 (RFC 8446) offers significant security improvements: mandatory "
                f"forward secrecy, removal of weak cipher suites, reduced handshake latency, "
                f"and encrypted certificate exchange. It should be the primary protocol."
            ),
            remediation=(
                "Enable TLS 1.3 on your server. It is supported by all modern TLS libraries. "
                "Example for Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "Example for Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={"address": ip, "port_number": port_num, "negotiated_version": tls_version},
        ))

    return findings


# ---------------------------------------------------------------------------
# Certificate findings
# ---------------------------------------------------------------------------

def _cert_findings(result: dict, session) -> list[Finding]:
    """Return findings for certificate issues (expiry, self-signed)."""
    ip = result["ip"]
    port_num = result["port"]
    port_fk = result["port_fk"]
    findings = []

    days = result.get("cert_expiry_days")

    if days is not None:
        if days <= 0:
            findings.append(Finding(
                session=session,
                source="tls_checker",
                check_type="cert_expired",
                severity="critical",
                title=f"TLS certificate expired on {ip}:{port_num}",
                description=(
                    f"The TLS certificate on {ip}:{port_num} has expired "
                    f"({abs(days)} day(s) ago). Clients will reject the connection with a "
                    f"certificate error, causing service disruption. Attackers may exploit "
                    f"this to present fraudulent certificates."
                ),
                remediation=(
                    "Renew the certificate immediately. Use automated renewal "
                    "(Let's Encrypt / ACME) to prevent future expirations."
                ),
                port=port_fk,
                target=f"{ip}:{port_num}",
                extra={"cert_expiry_days": days, "address": ip, "port_number": port_num},
            ))
        elif days <= 14:
            findings.append(Finding(
                session=session,
                source="tls_checker",
                check_type="cert_expiring_critical",
                severity="critical",
                title=f"TLS certificate expires in {days} day(s) on {ip}:{port_num}",
                description=(
                    f"The TLS certificate on {ip}:{port_num} expires in {days} day(s). "
                    f"Immediate renewal is required to prevent service disruption."
                ),
                remediation=(
                    "Renew the certificate immediately. "
                    "Implement automated renewal (Let's Encrypt / ACME) to avoid this in future."
                ),
                port=port_fk,
                target=f"{ip}:{port_num}",
                extra={"cert_expiry_days": days, "address": ip, "port_number": port_num},
            ))
        elif days <= 30:
            findings.append(Finding(
                session=session,
                source="tls_checker",
                check_type="cert_expiring_soon",
                severity="high",
                title=f"TLS certificate expires in {days} days on {ip}:{port_num}",
                description=(
                    f"The TLS certificate on {ip}:{port_num} expires in {days} days. "
                    f"Schedule renewal now to avoid service disruption."
                ),
                remediation=(
                    "Renew the certificate within the next few days. "
                    "Consider automated renewal via Let's Encrypt / ACME protocol."
                ),
                port=port_fk,
                target=f"{ip}:{port_num}",
                extra={"cert_expiry_days": days, "address": ip, "port_number": port_num},
            ))
        elif days <= 90:
            findings.append(Finding(
                session=session,
                source="tls_checker",
                check_type="cert_expiring",
                severity="medium",
                title=f"TLS certificate expires in {days} days on {ip}:{port_num}",
                description=(
                    f"The TLS certificate on {ip}:{port_num} expires in {days} days. "
                    f"Note: The CA/Browser Forum is reducing maximum certificate validity "
                    f"to 47 days by March 2029 — plan automated renewal now."
                ),
                remediation=(
                    "Plan certificate renewal. Set up automated renewal via "
                    "Let's Encrypt / ACME to future-proof against shorter validity windows."
                ),
                port=port_fk,
                target=f"{ip}:{port_num}",
                extra={"cert_expiry_days": days, "address": ip, "port_number": port_num},
            ))

    # Weak key
    key_type = result.get("cert_key_type")
    key_bits = result.get("cert_key_bits")
    if key_type == "RSA" and key_bits is not None and key_bits < 2048:
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="weak_rsa_key",
            severity="high",
            title=f"Weak RSA key ({key_bits}-bit) on {ip}:{port_num}",
            description=(
                f"The TLS certificate on {ip}:{port_num} uses a {key_bits}-bit RSA key. "
                f"RSA keys shorter than 2048 bits are considered insecure and can be "
                f"factored with modern hardware. NIST and CA/Browser Forum require "
                f"a minimum of 2048 bits."
            ),
            remediation=(
                "Generate a new RSA key pair with at least 2048 bits (recommended: 4096) "
                "or switch to ECDSA P-256 / P-384 for better performance at equivalent security."
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={"cert_key_type": key_type, "cert_key_bits": key_bits,
                   "address": ip, "port_number": port_num},
        ))
    elif key_type == "EC" and key_bits is not None and key_bits < 256:
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="weak_ec_key",
            severity="high",
            title=f"Weak EC key ({key_bits}-bit) on {ip}:{port_num}",
            description=(
                f"The TLS certificate on {ip}:{port_num} uses a {key_bits}-bit elliptic "
                f"curve key. EC keys shorter than 256 bits do not provide adequate security. "
                f"NIST recommends P-256 (256-bit) as the minimum curve."
            ),
            remediation=(
                "Generate a new ECDSA key pair using P-256 (256-bit) or P-384 (384-bit) curve."
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={"cert_key_type": key_type, "cert_key_bits": key_bits,
                   "address": ip, "port_number": port_num},
        ))
    elif key_type == "DSA":
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="dsa_key",
            severity="medium",
            title=f"Deprecated DSA key on {ip}:{port_num}",
            description=(
                f"The TLS certificate on {ip}:{port_num} uses a DSA key. "
                f"DSA is deprecated — it requires careful random number generation "
                f"(a single nonce reuse leaks the private key) and is no longer "
                f"recommended by NIST or supported by modern browsers."
            ),
            remediation=(
                "Replace the DSA key with RSA 2048+ or ECDSA P-256/P-384."
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={"cert_key_type": key_type, "cert_key_bits": key_bits,
                   "address": ip, "port_number": port_num},
        ))

    # Self-signed certificate
    if result.get("cert_self_signed"):
        findings.append(Finding(
            session=session,
            source="tls_checker",
            check_type="self_signed_cert",
            severity="high",
            title=f"Self-signed TLS certificate on {ip}:{port_num}",
            description=(
                f"The TLS certificate on {ip}:{port_num} is self-signed (issuer = subject). "
                f"Self-signed certificates provide no trust anchor — clients cannot verify the "
                f"server's identity, making the connection vulnerable to man-in-the-middle attacks. "
                f"Certificate revocation is also not possible for self-signed certs."
            ),
            remediation=(
                "Replace the self-signed certificate with one issued by a trusted CA. "
                "For public services, use Let's Encrypt (free, automated). "
                "For internal services, set up an internal CA with proper trust distribution."
            ),
            port=port_fk,
            target=f"{ip}:{port_num}",
            extra={"address": ip, "port_number": port_num},
        ))

    return findings


# ---------------------------------------------------------------------------
# SHA-1 signature finding
# ---------------------------------------------------------------------------

def _sig_algorithm_findings(result: dict, session) -> list[Finding]:
    """Return a finding if the certificate is signed with SHA-1."""
    if not result.get("cert_sig_sha1"):
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="tls_checker",
        check_type="sha1_cert_signature",
        severity="high",
        title=f"SHA-1 signed certificate on {ip}:{port_num}",
        description=(
            f"The TLS certificate on {ip}:{port_num} is signed with SHA-1 "
            f"(algorithm: {result.get('cert_sig_algorithm', 'unknown')}). "
            f"SHA-1 was demonstrated broken by the SHAttered collision attack in 2017. "
            f"All major browsers and CAs deprecated SHA-1 certificates. "
            f"An attacker with sufficient resources could forge a certificate."
        ),
        remediation=(
            "Reissue the certificate with a SHA-256 or SHA-384 signature. "
            "Most CAs have stopped issuing SHA-1 certificates since 2016."
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "cert_sig_algorithm": result.get("cert_sig_algorithm"),
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# SAN mismatch finding
# ---------------------------------------------------------------------------

def _san_mismatch_findings(result: dict, session) -> list[Finding]:
    """Return a finding if the hostname is not in the certificate's SAN list."""
    if not result.get("cert_san_mismatch"):
        return []

    ip = result["ip"]
    port_num = result["port"]
    san_list = result.get("cert_san_list", [])
    return [Finding(
        session=session,
        source="tls_checker",
        check_type="san_mismatch",
        severity="high",
        title=f"Certificate SAN mismatch on {ip}:{port_num}",
        description=(
            f"The TLS certificate on {ip}:{port_num} does not include the expected "
            f"hostname in its Subject Alternative Name (SAN) extension. "
            f"Certificate SANs: {', '.join(san_list) if san_list else '(none)'}. "
            f"Browsers and clients will reject this certificate with a name mismatch error, "
            f"and users may be trained to ignore certificate warnings."
        ),
        remediation=(
            "Reissue the certificate with the correct hostname(s) in the "
            "Subject Alternative Name extension. Include all domains and "
            "subdomains that the service serves."
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "cert_san_list": san_list,
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Certificate Transparency (SCT) finding
# ---------------------------------------------------------------------------

def _sct_findings(result: dict, session) -> list[Finding]:
    """Return a finding if no SCT extension is present in a CA-signed certificate."""
    # Only check CA-signed certs (self-signed certs never have SCTs)
    if result.get("cert_key_type") is None:
        return []  # No cert data available
    if result.get("cert_self_signed"):
        return []  # Self-signed — SCT check is irrelevant
    if result.get("cert_has_sct"):
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="tls_checker",
        check_type="no_sct",
        severity="medium",
        title=f"No Certificate Transparency SCT on {ip}:{port_num}",
        description=(
            f"The TLS certificate on {ip}:{port_num} does not contain a "
            f"Signed Certificate Timestamp (SCT). Since April 2018, Chrome requires "
            f"SCTs for all publicly trusted certificates (Certificate Transparency policy). "
            f"Apple's CT policy also mandates SCTs. Certificates without SCTs may be "
            f"rejected or flagged by browsers."
        ),
        remediation=(
            "Ensure your CA embeds SCT (Signed Certificate Timestamp) in certificates. "
            "Most public CAs do this by default. If using a private CA for public-facing "
            "services, submit certificates to CT logs."
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={"address": ip, "port_number": port_num},
    )]


# ---------------------------------------------------------------------------
# Untrusted CA finding
# ---------------------------------------------------------------------------

def _untrusted_ca_findings(result: dict, session) -> list[Finding]:
    """Return a finding if the certificate is not trusted by the system CA store."""
    # Skip if no cert data, or if already self-signed (separate finding covers that)
    if result.get("cert_key_type") is None:
        return []
    if result.get("cert_self_signed"):
        return []  # Already flagged by self_signed_cert finding
    if result.get("cert_trusted", True):
        return []  # Trusted — no finding

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="tls_checker",
        check_type="untrusted_ca",
        severity="high",
        title=f"Untrusted certificate authority on {ip}:{port_num}",
        description=(
            f"The TLS certificate on {ip}:{port_num} is not trusted by the system "
            f"certificate store. The certificate may be signed by an unknown CA, "
            f"have an incomplete chain (missing intermediate certificates), or the "
            f"CA may have been revoked. Clients will reject this certificate, and "
            f"users may be trained to click through security warnings — weakening "
            f"protection against man-in-the-middle attacks."
        ),
        remediation=(
            "Replace the certificate with one issued by a publicly trusted CA "
            "(e.g. Let's Encrypt, DigiCert, Sectigo). Ensure the full certificate "
            "chain is configured (leaf + intermediates). For internal services, "
            "distribute your internal CA to all clients via system trust stores."
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "cert_san_list": result.get("cert_san_list", []),
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Service-level remediation for unencrypted services
# ---------------------------------------------------------------------------

_TLS_REMEDIATION: dict[str, str] = {
    "smtp":          "Configure STARTTLS or migrate to SMTPS (port 465). Use a valid CA-signed certificate.",
    "submission":    "Enforce STARTTLS on port 587. Reject plaintext AUTH commands.",
    "imap":          "Enable STARTTLS on port 143 or migrate clients to IMAPS (993).",
    "pop3":          "Enable STARTTLS on port 110 or migrate clients to POP3S (995).",
    "ftp":           "Configure FTPS (AUTH TLS) on port 21, or replace with SFTP over SSH.",
    "ldap":          "Enable LDAPS on port 636 or enforce STARTTLS. Disable anonymous bind.",
    "mysql":         "Set require_secure_transport=ON in MySQL config and use --ssl-mode=REQUIRED for clients.",
    "postgresql":    "Set ssl=on in postgresql.conf and require hostssl entries in pg_hba.conf.",
    "ms-sql-s":      "Enable Force Encryption in SQL Server Configuration Manager.",
    "mongodb":       "Set net.tls.mode: requireTLS in mongod.conf.",
    "redis":         "Enable TLS in redis.conf (Redis 6+): set tls-port, tls-cert-file, tls-key-file.",
    "rdp":           "Set Security Layer to TLS in Group Policy: Computer Configuration → Admin Templates → Remote Desktop Services.",
    "ms-wbt-server": "Set Security Layer to TLS in Group Policy: Computer Configuration → Admin Templates → Remote Desktop Services.",
    "vnc":           "Tunnel VNC over SSH or replace with a TLS-native remote desktop solution.",
    "memcached":     "Upgrade to Memcached 1.5.13+ and enable TLS, or restrict the listener to localhost.",
    "couchdb":       "Set ssl.enable=true in CouchDB's local.ini and configure cert/key paths.",
    "elasticsearch": "Enable xpack.security.enabled: true and configure TLS in elasticsearch.yml.",
    "amqp":          "Use AMQPS (port 5671) and disable the plaintext AMQP listener.",
    "telnet":        "Disable Telnet immediately. Replace with SSH for all remote access.",
    "rlogin":        "Disable rlogin. Replace with SSH. rlogin has no authentication or encryption.",
    "rsh":           "Disable rsh. Replace with SSH. rsh is trivially exploitable on any network.",
    "rexec":         "Disable rexec. Replace with SSH. Credentials are transmitted in plaintext.",
}

_DEFAULT_TLS_REMEDIATION = (
    "Disable the plaintext listener and configure TLS. "
    "Consult your service documentation for TLS/SSL configuration."
)

_HTTP_REMEDIATION = (
    "Redirect all HTTP traffic to HTTPS using a 301 redirect. "
    "Configure a valid TLS certificate via Let's Encrypt or your CA. "
    "Set HSTS header (Strict-Transport-Security: max-age=31536000; includeSubDomains; preload) "
    "after fully migrating to HTTPS."
)


# ---------------------------------------------------------------------------
# HSTS finding (web HTTPS ports only)
# ---------------------------------------------------------------------------

def _hsts_finding(result: dict, session) -> list[Finding]:
    """
    Return a finding if the Strict-Transport-Security header is absent on an HTTPS port.

    HSTS prevents SSL stripping attacks (as documented in the MITM Attacks blog).
    Without it, a network attacker can intercept the HTTP redirect and keep the
    victim on an unencrypted connection even when the server supports HTTPS.
    """
    if not result.get("is_web") or not result.get("has_tls"):
        return []

    hsts = result.get("hsts_header")
    if hsts:
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="tls_checker",
        check_type="hsts_missing",
        severity="high",
        title=f"HSTS header missing on {ip}:{port_num}",
        description=(
            f"The HTTPS service on {ip}:{port_num} does not set the "
            f"Strict-Transport-Security (HSTS) header. Without HSTS, browsers "
            f"can still connect over HTTP, enabling SSL stripping attacks where "
            f"an attacker intercepts the HTTP-to-HTTPS redirect and downgrades "
            f"the connection to cleartext. This is a prerequisite for MITM attacks "
            f"against web clients."
        ),
        remediation=(
            "Add HSTS to all HTTPS responses:\n"
            "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "Ensure all subdomains also support HTTPS before enabling includeSubDomains. "
            "Consider submitting to the HSTS preload list at hstspreload.org for "
            "browser-native enforcement before any HTTP request is made."
        ),
        port=result["port_fk"],
        url=result.get("url_fk"),
        target=f"{ip}:{port_num}",
        extra={"address": ip, "port_number": port_num, "is_web": True},
    )]


# ---------------------------------------------------------------------------
# Main analyze function
# ---------------------------------------------------------------------------

def analyze(session, results: list[dict]) -> list[Finding]:
    """
    Build Finding objects from TLS probe results.

    For each port result, generates findings across multiple categories:
      - Unencrypted service (no TLS at all)
      - Deprecated protocol versions (TLS 1.0, 1.1)
      - TLS 1.3 not supported
      - Weak cipher suites (RC4, 3DES/Blowfish, NULL, EXPORT, SHA-1, CBC, RSA-KEX, anon)
      - Certificate issues (expired, near-expiry, self-signed)
      - HSTS missing (HTTPS web ports)
    """
    findings: list[Finding] = []

    for r in results:
        ip = r["ip"]
        port_num = r["port"]
        service = r["service"]
        has_tls = r["has_tls"]
        is_web = r["is_web"]
        is_inherently_insecure = r["inherently_insecure"]
        port_fk = r["port_fk"]
        url_fk = r.get("url_fk")
        display_svc = service.upper() if service else f"port {port_num}"

        if not has_tls:
            # ── No TLS at all ────────────────────────────────────────────
            if is_web:
                title = f"Unencrypted HTTP service on {ip}:{port_num}"
                description = (
                    f"The web service on {ip}:{port_num} is accessible over plain HTTP. "
                    f"All traffic — including session cookies, form data, and API calls — "
                    f"is transmitted in cleartext, enabling interception and SSL stripping attacks."
                )
                remediation = _HTTP_REMEDIATION
            elif is_inherently_insecure:
                title = f"Insecure protocol {display_svc} on {ip}:{port_num}"
                description = (
                    f"{display_svc} on {ip}:{port_num} is an inherently insecure protocol "
                    f"with no TLS support. All data — including credentials — is transmitted "
                    f"in plaintext and is trivially interceptable."
                )
                remediation = _TLS_REMEDIATION.get(service, _DEFAULT_TLS_REMEDIATION)
            else:
                title = f"Unencrypted {display_svc} on {ip}:{port_num}"
                description = (
                    f"{display_svc} on {ip}:{port_num} is accepting connections without TLS. "
                    f"Sensitive data exchanged over this service is exposed to interception "
                    f"and man-in-the-middle attacks."
                )
                remediation = _TLS_REMEDIATION.get(service, _DEFAULT_TLS_REMEDIATION)

            findings.append(Finding(
                session=session,
                source="tls_checker",
                check_type="unencrypted_service",
                severity="critical",
                title=title,
                description=description,
                remediation=remediation,
                port=port_fk,
                url=url_fk,
                target=f"{ip}:{port_num}",
                extra={
                    "service": service, "port_number": port_num, "address": ip,
                    "is_web": is_web, "scheme": r.get("scheme"),
                    "inherently_insecure": is_inherently_insecure,
                },
            ))

        else:
            # ── TLS present — check configuration quality ─────────────
            findings.extend(_protocol_findings(r, session))
            findings.extend(_weak_cipher_findings(r, session))
            findings.extend(_cert_findings(r, session))
            findings.extend(_sig_algorithm_findings(r, session))
            findings.extend(_san_mismatch_findings(r, session))
            findings.extend(_sct_findings(r, session))
            findings.extend(_untrusted_ca_findings(r, session))
            findings.extend(_hsts_finding(r, session))

    return findings
