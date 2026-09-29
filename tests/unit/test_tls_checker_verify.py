"""Tests for the tls_checker re-probe verifier.

Real finding shape (confirmed by reading apps/tls_checker/analyzer.py): the
design brief guessed check_type="weak_protocol" with extra["protocol"] — that
does not exist. The actual deprecated-protocol findings are two distinct
check_types emitted by ``analyzer._protocol_findings``:

  - check_type="tls10_supported", extra={"deprecated_version": "TLSv1", ...}
  - check_type="tls11_supported", extra={"deprecated_version": "TLSv1.1", ...}

Both share the same shape: the weak protocol name lives in
``extra["deprecated_version"]``, and ``finding.target`` is always ``"ip:port"``
(see every ``Finding(... target=f"{ip}:{port_num}")`` call in analyzer.py).
This verifier keys off ``extra["deprecated_version"]`` for both check_types.

Every other tls_checker check_type — cipher findings (null_cipher, rc4_cipher,
sweet32, cbc_cipher, no_forward_secrecy, ...), cert findings (cert_expired,
cert_expiring_*, weak_rsa_key, self_signed_cert, san_mismatch, no_sct,
untrusted_ca, sha1_cert_signature), tls13_not_supported (an absence, not a
weakness still "offered"), and unencrypted_service — has no re-probe rule in
this seed verifier and returns an honest INCONCLUSIVE rather than a guess.
"""
import pytest
from unittest.mock import patch


def _finding(check_type="tls10_supported", target="example.com:443", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(
        session=s, source="tls_checker", check_type=check_type,
        severity="high", title="TLS 1.0 supported", target=target,
        extra=extra or {"address": "example.com", "port_number": 443, "deprecated_version": "TLSv1"},
    )


@pytest.mark.django_db
def test_weak_protocol_still_offered_is_verified():
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.tls_checker.verify._probe_protocols", return_value={"TLSv1", "TLSv1.2"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED
    assert "TLSv1" in v.evidence


@pytest.mark.django_db
def test_weak_protocol_no_longer_offered_is_inconclusive():
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.tls_checker.verify._probe_protocols", return_value={"TLSv1.2", "TLSv1.3"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_connection_failure_is_inconclusive():
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.tls_checker.verify._probe_protocols", side_effect=OSError("refused")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_tls11_supported_is_also_covered():
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(check_type="tls11_supported",
                 extra={"address": "example.com", "port_number": 443, "deprecated_version": "TLSv1.1"})
    with patch("apps.tls_checker.verify._probe_protocols", return_value={"TLSv1.1"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED
    assert "TLSv1.1" in v.evidence


@pytest.mark.django_db
def test_check_type_without_reprobe_rule_is_inconclusive():
    """Cipher / cert / tls13_not_supported / unencrypted_service findings have
    no re-probe rule in this seed verifier -> honest inconclusive, no probe."""
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(check_type="cert_expired", extra={"cert_expiry_days": -5})
    with patch("apps.tls_checker.verify._probe_protocols") as mock_probe:
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
    mock_probe.assert_not_called()


@pytest.mark.django_db
def test_verifier_registered_in_tool_meta():
    from apps.core.engine.workflows import registry as R
    verifiers = R.get_tool_verifiers()
    assert "tls_checker" in verifiers
    assert callable(verifiers["tls_checker"])
