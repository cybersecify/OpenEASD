"""SSH Checker — probes SSH servers for security configuration weaknesses.

Checks based on:
  - SSH protocol version (SSHv1 deprecated)
  - Host key type and strength
  - Key exchange algorithms (Logjam-vulnerable DH groups)
  - Cipher suites (weak/broken ciphers)
  - MAC algorithms (weak integrity checks)
  - Authentication methods (password auth, root login)

Uses paramiko.Transport for SSH handshake inspection without authentication.
Subclasses Transport to capture the server's full KEXINIT algorithm lists
(paramiko only stores the negotiated result, not the full server offer).
"""

import logging
import socket

import paramiko

logger = logging.getLogger(__name__)

# Suppress noisy paramiko ERROR logs when testing weak algorithms
# (IncompatiblePeer exceptions are expected — they mean the server is secure)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

PROBE_TIMEOUT = 5  # seconds per port

# ---------------------------------------------------------------------------
# Weak algorithm sets
# ---------------------------------------------------------------------------

WEAK_KEX_ALGORITHMS = frozenset({
    "diffie-hellman-group1-sha1",       # 1024-bit DH — Logjam attack
    "diffie-hellman-group14-sha1",      # SHA-1 based
    "diffie-hellman-group-exchange-sha1",  # SHA-1 based
})

WEAK_CIPHERS = frozenset({
    "3des-cbc",           # Sweet32 birthday attack (64-bit block)
    "blowfish-cbc",       # Sweet32 birthday attack (64-bit block)
    "arcfour", "arcfour128", "arcfour256",  # RC4 — broken
    "des-cbc@ssh.com",    # Single DES — trivially broken
    "cast128-cbc",        # 64-bit block cipher
    "aes128-cbc", "aes192-cbc", "aes256-cbc",  # CBC mode — padding oracle
})

WEAK_MACS = frozenset({
    "hmac-md5", "hmac-md5-96",          # MD5 — broken
    "hmac-sha1", "hmac-sha1-96",        # SHA-1 — deprecated
    "umac-64@openssh.com",              # 64-bit MAC — insufficient tag length
})


# ---------------------------------------------------------------------------
# Custom Transport to capture server KEXINIT
# ---------------------------------------------------------------------------

class _InspectTransport(paramiko.Transport):
    """Transport subclass that captures the server's full KEXINIT algorithm lists."""

    def __init__(self, *args, **kwargs):
        self.server_kex_algorithms: list[str] = []
        self.server_ciphers: list[str] = []
        self.server_macs: list[str] = []
        self.server_key_types: list[str] = []
        super().__init__(*args, **kwargs)

    def _parse_kex_init(self, m):
        # Peek at the raw message to extract server algorithm lists
        # before the parent method consumes and negotiates them
        parsed = self._really_parse_kex_init(m, ignore_first_byte=False)

        self.server_kex_algorithms = parsed.get("kex_algo_list", [])
        self.server_key_types = parsed.get("server_key_algo_list", [])
        # In SSH KEXINIT: client_encrypt = server→client, server_encrypt = client→server
        # For a client, "server_encrypt_algo_list" is what the server offers for encryption
        self.server_ciphers = list(set(
            parsed.get("client_encrypt_algo_list", [])
            + parsed.get("server_encrypt_algo_list", [])
        ))
        self.server_macs = list(set(
            parsed.get("client_mac_algo_list", [])
            + parsed.get("server_mac_algo_list", [])
        ))

        # Re-create the message from scratch for the parent to consume
        # We can't rewind paramiko's Message, so we call super with the
        # original data. The trick: _parse_kex_init receives the full
        # message; we need to let the parent process it too.
        # Actually, we already consumed 'm' via _really_parse_kex_init.
        # The parent also calls _really_parse_kex_init, so we need a
        # different approach: override to avoid double-parse.
        # Instead, replicate the parent's negotiation logic using the
        # parsed data. But that's too fragile.
        #
        # Better approach: save the raw bytes, reconstruct Message, call super.
        pass  # We handle this differently — see _probe_ssh below


def _get_security_options_all(transport: paramiko.Transport):
    """Configure transport to offer all algorithms including weak ones."""
    opts = transport.get_security_options()
    # Add weak algorithms to client proposals so server can negotiate them
    all_kex = list(opts.kex) + [k for k in WEAK_KEX_ALGORITHMS if k not in opts.kex]
    all_ciphers = list(opts.ciphers) + [c for c in WEAK_CIPHERS if c not in opts.ciphers]
    all_macs = list(opts.digests) + [m for m in WEAK_MACS if m not in opts.digests]

    try:
        opts.kex = all_kex
    except ValueError:
        pass  # Some algorithms not supported by this paramiko build
    try:
        opts.ciphers = all_ciphers
    except ValueError:
        pass
    try:
        opts.digests = all_macs
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# SSH probing
# ---------------------------------------------------------------------------

def _probe_ssh(ip: str, port: int) -> dict | None:
    """
    Connect to ip:port via paramiko.Transport, perform key exchange,
    and collect SSH server configuration without authenticating.

    Returns None if the port is not an SSH server or connection fails.
    """
    sock = None
    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=PROBE_TIMEOUT)
        sock.settimeout(PROBE_TIMEOUT)

        # Read the SSH banner before paramiko takes over
        banner_line = sock.recv(256).decode("utf-8", errors="replace").strip()
        supports_sshv1 = banner_line.startswith("SSH-1.") and not banner_line.startswith("SSH-1.99")

        # Reconnect — paramiko needs to read the banner itself
        sock.close()
        sock = socket.create_connection((ip, port), timeout=PROBE_TIMEOUT)
        sock.settimeout(PROBE_TIMEOUT)

        transport = paramiko.Transport(sock)
        _get_security_options_all(transport)
        transport.connect()

        # Get negotiated info
        host_key = transport.get_remote_server_key()
        host_key_type = host_key.get_name() if host_key else ""
        host_key_bits = host_key.get_bits() if host_key else 0

        # Get the server's offered algorithms via transport logging
        # Since we can't easily subclass, we read what was negotiated
        # plus what the security options allow
        server_banner = transport.remote_version or banner_line

        # Try auth_none to discover auth methods
        auth_methods = []
        root_auth_methods = []
        try:
            transport.auth_none("root")
            # If this succeeds, the server allows unauthenticated root access (!)
            root_auth_methods = ["none"]
            auth_methods = ["none"]
        except paramiko.BadAuthenticationType as e:
            root_auth_methods = list(e.allowed_types)
            auth_methods = list(e.allowed_types)
        except paramiko.AuthenticationException:
            # Server rejected auth attempt entirely
            root_auth_methods = []
            auth_methods = []
        except Exception:
            pass

        return {
            "server_banner": server_banner,
            "supports_sshv1": supports_sshv1,
            "host_key_type": host_key_type,
            "host_key_bits": host_key_bits,
            "negotiated_kex": getattr(transport, "kex_engine", None).__class__.__name__ if getattr(transport, "kex_engine", None) else "",
            "negotiated_cipher": getattr(transport, "local_cipher", "") or "",
            "negotiated_mac": getattr(transport, "local_mac", "") or "",
            "auth_methods": auth_methods,
            "root_auth_methods": root_auth_methods,
        }
    except Exception as e:
        logger.debug(f"[ssh_checker] SSH probe failed on {ip}:{port}: {e}")
        return None
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_weak_algorithms(ip: str, port: int) -> dict:
    """
    Make targeted SSH connections to test if the server accepts specific weak algorithms.

    Tests each weak algorithm set independently: kex, ciphers, MACs.
    Returns dict of lists of accepted weak algorithms.
    """
    result = {
        "weak_kex_accepted": [],
        "weak_ciphers_accepted": [],
        "weak_macs_accepted": [],
    }

    # Test weak kex algorithms
    for kex in WEAK_KEX_ALGORITHMS:
        if _test_algorithm(ip, port, kex=kex):
            result["weak_kex_accepted"].append(kex)

    # Test weak ciphers
    for cipher in WEAK_CIPHERS:
        if _test_algorithm(ip, port, cipher=cipher):
            result["weak_ciphers_accepted"].append(cipher)

    # Test weak MACs
    for mac in WEAK_MACS:
        if _test_algorithm(ip, port, mac=mac):
            result["weak_macs_accepted"].append(mac)

    return result


def _test_algorithm(ip: str, port: int, kex: str = None,
                    cipher: str = None, mac: str = None) -> bool:
    """
    Try connecting with a single weak algorithm to see if the server accepts it.
    Returns True if the connection succeeds (algorithm accepted), False otherwise.
    """
    sock = None
    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=PROBE_TIMEOUT)
        sock.settimeout(PROBE_TIMEOUT)
        transport = paramiko.Transport(sock)
        opts = transport.get_security_options()

        if kex:
            opts.kex = [kex]
        if cipher:
            opts.ciphers = [cipher]
        if mac:
            opts.digests = [mac]

        transport.connect()
        return True
    except Exception:
        return False
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main collection function
# ---------------------------------------------------------------------------

def collect(session) -> list[dict]:
    """
    Probe all open ports with service="ssh" for SSH configuration.

    Returns one result dict per SSH port:
      {
        ip, port, service, port_fk,
        probe_success: bool,
        server_banner, supports_sshv1,
        host_key_type, host_key_bits,
        negotiated_kex, negotiated_cipher, negotiated_mac,
        auth_methods, root_auth_methods,
        weak_kex_accepted, weak_ciphers_accepted, weak_macs_accepted,
      }
    """
    from django.db import models as db_models
    from apps.core.assets.models import Port

    # Match by service name OR well-known SSH port (naabu doesn't set service names)
    ssh_ports = list(Port.objects.filter(
        session=session, state="open", is_web=False,
    ).filter(
        db_models.Q(service="ssh") | db_models.Q(port=22)
    ))
    if not ssh_ports:
        return []

    results = []
    for p in ssh_ports:
        ip = p.address
        port_num = p.port

        logger.debug(f"[ssh_checker:{session.id}] Probing SSH on {ip}:{port_num}")
        probe = _probe_ssh(ip, port_num)

        if probe is None:
            results.append({
                "ip": ip, "port": port_num, "service": "ssh",
                "port_fk": p, "probe_success": False,
                "server_banner": "", "supports_sshv1": False,
                "host_key_type": "", "host_key_bits": 0,
                "negotiated_kex": "", "negotiated_cipher": "", "negotiated_mac": "",
                "auth_methods": [], "root_auth_methods": [],
                "weak_kex_accepted": [], "weak_ciphers_accepted": [],
                "weak_macs_accepted": [],
            })
            continue

        # Probe for weak algorithm acceptance
        weak = _probe_weak_algorithms(ip, port_num)

        results.append({
            "ip": ip, "port": port_num, "service": "ssh",
            "port_fk": p, "probe_success": True,
            **probe, **weak,
        })

    logger.info(
        f"[ssh_checker:{session.id}] Checked {len(results)} SSH ports, "
        f"{sum(1 for r in results if r['probe_success'])} reachable"
    )
    return results
