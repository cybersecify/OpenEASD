"""Re-probe verifier for ssh_checker findings.

Real finding shape (confirmed by reading analyzer.py + collector.py, not the
design brief's guess): there is no check_type="weak_kex" and no
extra["algorithm"]. ``analyzer.py`` emits seven check_types, all sourced from
the same per-port probe dict ``collector.collect()`` builds out of
``collector._probe_ssh`` (banner/host-key/auth-method negotiation) and
``collector._probe_weak_algorithms`` (targeted per-algorithm reconnects):

  - check_type="sshv1_supported"     extra={"server_banner": ..., ...}
      -> re-probable: still true iff the server's banner still negotiates SSHv1
         (``probe["supports_sshv1"]``).
  - check_type="weak_ssh_host_key"   extra={"host_key_type": ..., "host_key_bits": ...}
      -> re-probable: still true iff the negotiated host key is still ssh-dss,
         or still ssh-rsa under 2048 bits (the same two conditions
         ``analyzer._weak_host_key_finding`` checks).
  - check_type="weak_ssh_kex"        extra={"weak_kex": [...]}
      -> re-probable: still true iff any algorithm in extra["weak_kex"] is
         still accepted (``probe["weak_kex_accepted"]``).
  - check_type="weak_ssh_cipher"     extra={"weak_ciphers": [...]}
      -> same pattern against ``probe["weak_ciphers_accepted"]``.
  - check_type="weak_ssh_mac"        extra={"weak_macs": [...]}
      -> same pattern against ``probe["weak_macs_accepted"]``.
  - check_type="ssh_password_auth"   extra={"auth_methods": [...]}
      -> re-probable: still true iff "password" is still an offered auth
         method (``probe["auth_methods"]``).
  - check_type="ssh_root_login"      extra={"root_auth_methods": [...]}
      -> re-probable: still true iff the server still offers ANY auth method
         for root (``probe["root_auth_methods"]`` non-empty) — matches
         ``analyzer._root_login_finding``'s own condition.

Every one of ssh_checker's check_types turns out to be cleanly re-probable
because they all boil down to "is this still in the set the server offers
right now" against the collector's own live probe — unlike web_checker/
tls_checker, there is no leftover "no re-probe rule" family here.

Active (touches the target) — gated upstream by DomainAuthorization in
verify_session, same as the tool itself. Note ssh_password_auth/ssh_root_login
re-probing performs the same unauthenticated auth_none() handshake the
collector itself already performs during a normal scan — no new attack
surface is added.

Reuses ``apps/ssh_checker/collector.py``'s own ``_probe_ssh`` and
``_probe_weak_algorithms`` functions (already factored as plain
``(ip, port) -> dict`` helpers — no extraction/refactor was needed) via the
thin, directly patchable ``_probe`` wrapper below.
"""
from apps.core.engine.verification.verdict import Verdict


def _split_target(target: str):
    host, _, port = (target or "").partition(":")
    return host, int(port) if port else 22


def _probe(host: str, port: int) -> dict:
    """Re-probe ``host:port`` and return the same signals
    ``collector.collect()`` stores per SSH port (merged base probe +
    weak-algorithm probe). Raises on connection failure so callers can turn
    any failure into an honest INCONCLUSIVE rather than a guess."""
    from apps.ssh_checker.collector import _probe_ssh, _probe_weak_algorithms

    base = _probe_ssh(host, port)
    if base is None:
        raise ConnectionError(f"SSH probe failed for {host}:{port}")
    weak = _probe_weak_algorithms(host, port)
    return {**base, **weak}


def _verify_sshv1(finding, probe):
    if probe.get("supports_sshv1"):
        return Verdict(Verdict.VERIFIED, evidence="SSHv1 still supported")
    return Verdict(Verdict.INCONCLUSIVE, detail="SSHv1 no longer supported")


def _verify_weak_host_key(finding, probe):
    extra = finding.extra or {}
    key_type = extra.get("host_key_type", "")
    now_type = probe.get("host_key_type", "")
    now_bits = probe.get("host_key_bits", 0)

    if key_type == "ssh-dss" and now_type == "ssh-dss":
        return Verdict(Verdict.VERIFIED, evidence="DSA host key still in use")
    if key_type == "ssh-rsa" and now_type == "ssh-rsa" and now_bits and now_bits < 2048:
        return Verdict(Verdict.VERIFIED, evidence=f"{now_bits}-bit RSA host key still in use")
    return Verdict(Verdict.INCONCLUSIVE, detail=f"host key now {now_type} ({now_bits}-bit)")


def _verify_weak_list(extra_key: str, probe_key: str):
    """Build a handler for the weak_ssh_{kex,cipher,mac} family: verified iff
    any algorithm recorded in ``finding.extra[extra_key]`` is still present in
    ``probe[probe_key]``."""

    def handler(finding, probe):
        weak = set((finding.extra or {}).get(extra_key, []))
        offered = set(probe.get(probe_key, []))
        still = weak & offered
        if still:
            return Verdict(Verdict.VERIFIED, evidence=f"still offered: {sorted(still)}")
        return Verdict(Verdict.INCONCLUSIVE, detail=f"no longer offered (was {sorted(weak)})")

    return handler


def _verify_password_auth(finding, probe):
    if "password" in probe.get("auth_methods", []):
        return Verdict(Verdict.VERIFIED, evidence="password auth still enabled")
    return Verdict(Verdict.INCONCLUSIVE, detail="password auth no longer offered")


def _verify_root_login(finding, probe):
    root_methods = probe.get("root_auth_methods", [])
    if root_methods:
        return Verdict(
            Verdict.VERIFIED, evidence=f"root login still permitted via {sorted(root_methods)}"
        )
    return Verdict(Verdict.INCONCLUSIVE, detail="root login no longer permitted")


_CHECK_HANDLERS = {
    "sshv1_supported": _verify_sshv1,
    "weak_ssh_host_key": _verify_weak_host_key,
    "weak_ssh_kex": _verify_weak_list("weak_kex", "weak_kex_accepted"),
    "weak_ssh_cipher": _verify_weak_list("weak_ciphers", "weak_ciphers_accepted"),
    "weak_ssh_mac": _verify_weak_list("weak_macs", "weak_macs_accepted"),
    "ssh_password_auth": _verify_password_auth,
    "ssh_root_login": _verify_root_login,
}


def verify_finding(finding) -> Verdict:
    """Re-probe a single ssh_checker finding.

    Every check_type ssh_checker emits has a re-probe rule (see module
    docstring); an unrecognized check_type — e.g. from a future tool change —
    is still honestly INCONCLUSIVE rather than a guess.
    """
    handler = _CHECK_HANDLERS.get(finding.check_type)
    if handler is None:
        return Verdict(Verdict.INCONCLUSIVE, detail=f"no re-probe rule for {finding.check_type}")

    host, port = _split_target(finding.target)
    try:
        probe = _probe(host, port)
    except Exception as exc:  # noqa: BLE001 — any probe failure -> inconclusive, never raise
        return Verdict(Verdict.INCONCLUSIVE, detail=f"probe failed: {exc}")

    return handler(finding, probe)
