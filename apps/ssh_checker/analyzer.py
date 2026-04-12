"""SSH Checker analyzer — converts probe results into Finding objects.

Finding categories:
  - SSHv1 protocol support (deprecated, broken)
  - Weak host key (DSA, small RSA)
  - Weak key exchange algorithms (Logjam-vulnerable DH groups)
  - Weak ciphers (RC4, 3DES, DES, CBC mode)
  - Weak MACs (MD5, SHA-1, 64-bit tags)
  - Password authentication enabled (brute-force risk)
  - Root login permitted (direct root access)
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SSHv1 protocol
# ---------------------------------------------------------------------------

def _sshv1_finding(result: dict, session) -> list[Finding]:
    if not result.get("supports_sshv1"):
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="ssh_checker",
        check_type="sshv1_supported",
        severity="critical",
        title=f"SSHv1 protocol supported on {ip}:{port_num}",
        description=(
            f"The SSH server at {ip}:{port_num} supports SSH protocol version 1. "
            f"SSHv1 has fundamental cryptographic flaws — it uses CRC-32 for integrity "
            f"(trivially forgeable), allows session hijacking, and has no protection "
            f"against man-in-the-middle attacks. SSHv1 has been deprecated since 2006 (RFC 4253)."
        ),
        remediation=(
            "Disable SSH protocol version 1 immediately. In OpenSSH, ensure the "
            "configuration does NOT include 'Protocol 1' or 'Protocol 1,2'. "
            "Modern OpenSSH only supports protocol 2 by default."
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "server_banner": result.get("server_banner", ""),
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Weak host key
# ---------------------------------------------------------------------------

def _weak_host_key_finding(result: dict, session) -> list[Finding]:
    key_type = result.get("host_key_type", "")
    key_bits = result.get("host_key_bits", 0)
    ip = result["ip"]
    port_num = result["port"]

    if key_type == "ssh-dss":
        return [Finding(
            session=session,
            source="ssh_checker",
            check_type="weak_ssh_host_key",
            severity="high",
            title=f"DSA host key on {ip}:{port_num}",
            description=(
                f"The SSH server at {ip}:{port_num} uses a DSA host key. "
                f"DSA is deprecated — it is limited to 1024-bit keys (FIPS 186-2), "
                f"requires careful random number generation (a single nonce reuse "
                f"leaks the private key), and was removed from OpenSSH 7.0+."
            ),
            remediation=(
                "Generate a new host key using Ed25519 (preferred) or ECDSA P-256/P-384. "
                "Remove the DSA key: delete /etc/ssh/ssh_host_dsa_key* and remove "
                "'HostKey /etc/ssh/ssh_host_dsa_key' from sshd_config."
            ),
            port=result["port_fk"],
            target=f"{ip}:{port_num}",
            extra={
                "host_key_type": key_type, "host_key_bits": key_bits,
                "address": ip, "port_number": port_num,
            },
        )]

    if key_type == "ssh-rsa" and key_bits < 2048:
        return [Finding(
            session=session,
            source="ssh_checker",
            check_type="weak_ssh_host_key",
            severity="high",
            title=f"Weak RSA host key ({key_bits}-bit) on {ip}:{port_num}",
            description=(
                f"The SSH server at {ip}:{port_num} uses a {key_bits}-bit RSA host key. "
                f"RSA keys shorter than 2048 bits can be factored with modern hardware. "
                f"NIST recommends a minimum of 2048 bits, with 3072+ bits for long-term security."
            ),
            remediation=(
                "Generate a new RSA host key with at least 3072 bits: "
                "'ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key'. "
                "Alternatively, switch to Ed25519: 'ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key'."
            ),
            port=result["port_fk"],
            target=f"{ip}:{port_num}",
            extra={
                "host_key_type": key_type, "host_key_bits": key_bits,
                "address": ip, "port_number": port_num,
            },
        )]

    return []


# ---------------------------------------------------------------------------
# Weak key exchange algorithms
# ---------------------------------------------------------------------------

def _weak_kex_findings(result: dict, session) -> list[Finding]:
    weak_kex = result.get("weak_kex_accepted", [])
    if not weak_kex:
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="ssh_checker",
        check_type="weak_ssh_kex",
        severity="high",
        title=f"Weak SSH key exchange algorithms on {ip}:{port_num}",
        description=(
            f"The SSH server at {ip}:{port_num} accepts weak key exchange algorithms: "
            f"{', '.join(sorted(weak_kex))}. "
            f"diffie-hellman-group1-sha1 uses a 1024-bit DH group vulnerable to the "
            f"Logjam attack. SHA-1 based exchanges are deprecated due to collision attacks."
        ),
        remediation=(
            "Disable weak key exchange algorithms in sshd_config. Use only:\n"
            "  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "weak_kex": sorted(weak_kex),
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Weak ciphers
# ---------------------------------------------------------------------------

def _weak_cipher_findings(result: dict, session) -> list[Finding]:
    weak_ciphers = result.get("weak_ciphers_accepted", [])
    if not weak_ciphers:
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="ssh_checker",
        check_type="weak_ssh_cipher",
        severity="high",
        title=f"Weak SSH cipher suites on {ip}:{port_num}",
        description=(
            f"The SSH server at {ip}:{port_num} accepts weak cipher algorithms: "
            f"{', '.join(sorted(weak_ciphers))}. "
            f"RC4 (arcfour) is cryptographically broken. 3DES and Blowfish use 64-bit "
            f"blocks vulnerable to Sweet32 birthday attacks. CBC mode ciphers are "
            f"vulnerable to padding oracle attacks (CVE-2008-5161)."
        ),
        remediation=(
            "Restrict ciphers to AEAD modes in sshd_config:\n"
            "  Ciphers chacha20-poly1305@openssh.com,"
            "aes128-gcm@openssh.com,aes256-gcm@openssh.com,"
            "aes128-ctr,aes192-ctr,aes256-ctr"
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "weak_ciphers": sorted(weak_ciphers),
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Weak MACs
# ---------------------------------------------------------------------------

def _weak_mac_findings(result: dict, session) -> list[Finding]:
    weak_macs = result.get("weak_macs_accepted", [])
    if not weak_macs:
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="ssh_checker",
        check_type="weak_ssh_mac",
        severity="medium",
        title=f"Weak SSH MAC algorithms on {ip}:{port_num}",
        description=(
            f"The SSH server at {ip}:{port_num} accepts weak MAC algorithms: "
            f"{', '.join(sorted(weak_macs))}. "
            f"MD5-based MACs use a broken hash function. SHA-1 MACs are deprecated. "
            f"64-bit MACs (umac-64) have insufficient tag length for modern security."
        ),
        remediation=(
            "Restrict MACs to SHA-2 based algorithms in sshd_config:\n"
            "  MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
            "umac-128-etm@openssh.com"
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "weak_macs": sorted(weak_macs),
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Password authentication
# ---------------------------------------------------------------------------

def _password_auth_finding(result: dict, session) -> list[Finding]:
    if "password" not in result.get("auth_methods", []):
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="ssh_checker",
        check_type="ssh_password_auth",
        severity="medium",
        title=f"SSH password authentication enabled on {ip}:{port_num}",
        description=(
            f"The SSH server at {ip}:{port_num} accepts password authentication. "
            f"Password auth is vulnerable to brute-force and credential stuffing attacks. "
            f"Compromised passwords from other services can be reused to gain SSH access."
        ),
        remediation=(
            "Disable password authentication in sshd_config:\n"
            "  PasswordAuthentication no\n"
            "  ChallengeResponseAuthentication no\n"
            "Use public key authentication exclusively. Distribute keys via "
            "ssh-copy-id or a configuration management tool."
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "auth_methods": result.get("auth_methods", []),
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Root login
# ---------------------------------------------------------------------------

def _root_login_finding(result: dict, session) -> list[Finding]:
    root_methods = result.get("root_auth_methods", [])
    if not root_methods:
        return []

    ip = result["ip"]
    port_num = result["port"]
    return [Finding(
        session=session,
        source="ssh_checker",
        check_type="ssh_root_login",
        severity="medium",
        title=f"SSH root login permitted on {ip}:{port_num}",
        description=(
            f"The SSH server at {ip}:{port_num} permits authentication as root "
            f"(allowed methods: {', '.join(root_methods)}). "
            f"Direct root login bypasses audit trails — actions cannot be attributed "
            f"to individual users. It also doubles the attack surface by exposing "
            f"the highest-privilege account to brute-force and credential attacks."
        ),
        remediation=(
            "Disable root login in sshd_config:\n"
            "  PermitRootLogin no\n"
            "Use a regular user account with sudo for privilege escalation. "
            "If root access is required for automation, use 'PermitRootLogin prohibit-password' "
            "to allow key-based root login only."
        ),
        port=result["port_fk"],
        target=f"{ip}:{port_num}",
        extra={
            "root_auth_methods": root_methods,
            "address": ip, "port_number": port_num,
        },
    )]


# ---------------------------------------------------------------------------
# Main analyze function
# ---------------------------------------------------------------------------

def analyze(session, results: list[dict]) -> list[Finding]:
    """
    Build Finding objects from SSH probe results.

    For each SSH port result, generates findings across:
      - SSHv1 protocol support
      - Weak host key (DSA, short RSA)
      - Weak key exchange algorithms
      - Weak ciphers
      - Weak MACs
      - Password authentication enabled
      - Root login permitted
    """
    findings: list[Finding] = []

    for r in results:
        if not r.get("probe_success"):
            continue
        findings.extend(_sshv1_finding(r, session))
        findings.extend(_weak_host_key_finding(r, session))
        findings.extend(_weak_kex_findings(r, session))
        findings.extend(_weak_cipher_findings(r, session))
        findings.extend(_weak_mac_findings(r, session))
        findings.extend(_password_auth_finding(r, session))
        findings.extend(_root_login_finding(r, session))

    return findings
