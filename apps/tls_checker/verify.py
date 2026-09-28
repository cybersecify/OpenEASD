"""Re-probe verifier for tls_checker findings.

Real finding shape (confirmed by reading analyzer.py, not the design brief's
guess): there is no check_type="weak_protocol" and no extra["protocol"]. The
deprecated-protocol findings that ``analyzer._protocol_findings`` actually
emits are two check_types:

  - check_type="tls10_supported", extra={"deprecated_version": "TLSv1", ...}
  - check_type="tls11_supported", extra={"deprecated_version": "TLSv1.1", ...}

Both share the same shape — the weak protocol name that is "still offered"
lives in ``extra["deprecated_version"]`` — so this verifier keys off that
field for both check_types rather than a per-check_type table. ``finding.target``
is always ``"ip:port"`` (every Finding in analyzer.py sets
``target=f"{ip}:{port_num}"``), so it splits cleanly into host/port for the
re-probe.

Every other tls_checker check_type is honestly left un-reprobed here:
  - Cipher findings (null_cipher, export_cipher, rc4_cipher, anon_cipher,
    sweet32, des_cipher, md5_cipher, sha1_cipher, cbc_cipher,
    no_forward_secrecy) would need a full nmap ssl-enum-ciphers re-run
    (external binary, not a cheap stdlib re-probe) to confirm a *specific*
    cipher is still negotiated — out of scope for this seed verifier.
  - tls13_not_supported records an *absence* ("no TLS 1.3"), not a weak
    thing "still offered" — re-probing it is a different, asymmetric
    question (would need to prove TLS 1.3 is still unavailable) left for a
    later verifier.
  - Certificate findings (cert_expired, cert_expiring_*, weak_rsa_key,
    weak_ec_key, dsa_key, self_signed_cert, sha1_cert_signature,
    san_mismatch, no_sct, untrusted_ca) and unencrypted_service are not
    handled by this seed verifier.

Active (touches the target) — gated upstream by DomainAuthorization in
verify_session, same as the tool itself.

Reuses ``apps/tls_checker/collector.py``'s ``_check_legacy_protocol_support``
connection helper (same stdlib ssl approach the collector itself uses to
populate ``supports_tls10``/``supports_tls11``) rather than reinventing the
TLS-version-pinned handshake probe.
"""
from apps.core.engine.verification.verdict import Verdict
from apps.tls_checker.collector import _check_legacy_protocol_support

# check_types for which extra["deprecated_version"] names a legacy TLS
# protocol version this verifier knows how to re-probe by still-offered check.
_DEPRECATED_PROTOCOL_CHECK_TYPES = {"tls10_supported", "tls11_supported"}

# Maps collector._check_legacy_protocol_support's boolean keys to the exact
# "deprecated_version" strings analyzer._protocol_findings stores in extra.
_LEGACY_KEY_TO_VERSION = {"tls10": "TLSv1", "tls11": "TLSv1.1"}


def _split_target(target: str):
    host, _, port = (target or "").partition(":")
    return host, int(port) if port else 443


def _probe_protocols(host: str, port: int) -> set:
    """Return the set of deprecated TLS protocol version strings ``host:port``
    still accepts (values match analyzer's ``extra["deprecated_version"]``:
    "TLSv1" / "TLSv1.1")."""
    legacy = _check_legacy_protocol_support(host, port)
    return {version for key, version in _LEGACY_KEY_TO_VERSION.items() if legacy.get(key)}


def verify_finding(finding) -> Verdict:
    """Re-probe a single tls_checker finding.

    Only the deprecated-protocol-still-supported family (tls10_supported /
    tls11_supported) has a re-probe rule here; every other check_type is
    honestly INCONCLUSIVE (no re-probe rule yet), never a guess.
    """
    if finding.check_type not in _DEPRECATED_PROTOCOL_CHECK_TYPES:
        return Verdict(Verdict.INCONCLUSIVE, detail=f"no re-probe rule for {finding.check_type}")

    weak = (finding.extra or {}).get("deprecated_version")
    if not weak:
        return Verdict(Verdict.INCONCLUSIVE, detail="missing deprecated_version in extra")

    host, port = _split_target(finding.target)
    try:
        offered = _probe_protocols(host, port)
    except Exception as exc:  # noqa: BLE001 — any probe failure -> inconclusive, never raise
        return Verdict(Verdict.INCONCLUSIVE, detail=f"probe failed: {exc}")

    if weak in offered:
        return Verdict(
            Verdict.VERIFIED,
            evidence=f"{weak} still offered ({sorted(offered)})",
        )
    return Verdict(
        Verdict.INCONCLUSIVE,
        detail=f"{weak} no longer offered",
        evidence=str(sorted(offered)),
    )
