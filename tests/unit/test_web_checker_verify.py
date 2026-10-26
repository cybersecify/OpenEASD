"""Tests for the web_checker re-probe verifier.

Real finding shape (confirmed by reading apps/web_checker/analyzer.py): a
missing-security-header finding does NOT use check_type="missing_header" (that
was illustrative in the design brief) — analyzer._security_header_findings /
_hsts_findings emit one of check_type in {missing_csp, missing_xfo,
missing_xcto, missing_permissions_policy, missing_referrer_policy,
missing_hsts}, each with extra={"header": "<Header-Name>", "url": ...}. These
tests use the real check_type ("missing_csp") with the real extra shape.
"""
import pytest
from unittest.mock import patch


def _finding(check_type="missing_csp", target="https://example.com", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(session=s, source="web_checker", check_type=check_type,
                                  severity="high", title="Missing CSP", target=target,
                                  extra=extra or {"header": "Content-Security-Policy", "url": target})


@pytest.mark.django_db
def test_missing_header_still_missing_is_verified():
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.web_checker.verify._fetch_headers", return_value={"server": "nginx"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED
    assert "Content-Security-Policy" in v.evidence


@pytest.mark.django_db
def test_missing_header_now_present_is_inconclusive():
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.web_checker.verify._fetch_headers",
               return_value={"content-security-policy": "default-src 'self'"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_fetch_failure_is_inconclusive():
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.web_checker.verify._fetch_headers", side_effect=OSError("timeout")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_missing_hsts_still_missing_is_verified():
    """missing_hsts is a separate check_type from the _HEADER_CHECKS table but
    shares the same extra['header'] shape (see analyzer._hsts_findings)."""
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(check_type="missing_hsts",
                 extra={"header": "Strict-Transport-Security", "url": "https://example.com"})
    with patch("apps.web_checker.verify._fetch_headers", return_value={}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED
    assert "Strict-Transport-Security" in v.evidence


@pytest.mark.django_db
def test_check_type_without_reprobe_rule_is_inconclusive():
    """cookie/cors/server-disclosure/directory-listing/security-txt findings have
    no re-probe rule in this seed verifier -> honest inconclusive, no fetch."""
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(check_type="cookie_missing_secure",
                 extra={"cookie_name": "session", "url": "https://example.com"})
    with patch("apps.web_checker.verify._fetch_headers") as mock_fetch:
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
    mock_fetch.assert_not_called()


@pytest.mark.django_db
def test_verifier_registered_in_tool_meta():
    from apps.core.engine.workflows import registry as R
    verifiers = R.get_tool_verifiers()
    assert "web_checker" in verifiers
    assert callable(verifiers["web_checker"])
