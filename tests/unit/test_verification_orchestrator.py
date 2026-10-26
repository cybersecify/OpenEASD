import pytest
from unittest.mock import patch
from apps.core.engine.verification.verdict import Verdict


def _session(status="completed"):
    from apps.core.engine.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status=status)


def _finding(s, source="web_checker", sev="high", **kw):
    from apps.core.data.findings.models import Finding
    return Finding.objects.create(session=s, source=source, check_type="missing_header",
                                  severity=sev, title="t", target="example.com", **kw)


@pytest.mark.django_db
def test_below_threshold_left_unverified():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, sev="low")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"web_checker": lambda finding: Verdict(Verdict.VERIFIED)}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "unverified"


@pytest.mark.django_db
def test_passive_tool_verified_writes_verdict_and_evidence():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="breach_check", sev="high")
    v = Verdict(Verdict.VERIFIED, evidence="still 3 breaches", detail="XposedOrNot")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: v}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "verified"
    assert f.verified_at is not None
    assert f.extra["verification"]["evidence"] == "still 3 breaches"
    assert f.extra["verification"]["method"] == "reprobe"


@pytest.mark.django_db
def test_active_tool_without_authorization_is_inconclusive_no_call():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="nuclei", sev="high")  # nuclei is active
    called = {"n": 0}
    def _verifier(finding):
        called["n"] += 1
        return Verdict(Verdict.VERIFIED)
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"nuclei": _verifier}), \
         patch("apps.core.engine.verification.verifier._authorized_for", return_value=False):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "inconclusive"
    assert called["n"] == 0  # never re-probed the target without authorization


@pytest.mark.django_db
def test_verifier_exception_is_inconclusive_and_scan_unaffected():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="breach_check", sev="high")
    def _boom(finding):
        raise RuntimeError("network down")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": _boom}):
        verify_session(s, threshold="medium")  # must not raise
    f.refresh_from_db()
    assert f.verification_status == "inconclusive"


@pytest.mark.django_db
def test_tool_without_verifier_stays_unverified():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="subfinder", sev="high")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers", return_value={}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "unverified"


@pytest.mark.django_db
def test_idempotent_rerun_overwrites_not_appends():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="breach_check", sev="high")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: Verdict(Verdict.VERIFIED, evidence="a")}):
        verify_session(s, threshold="medium")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: Verdict(Verdict.INCONCLUSIVE, evidence="b")}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "inconclusive"
    assert f.extra["verification"]["evidence"] == "b"


@pytest.mark.django_db
def test_verify_one_finding_active_tool_without_authorization_is_inconclusive_no_call():
    """Mirrors test_active_tool_without_authorization_is_inconclusive_no_call,
    but for the single-finding on-demand path — this is the security gate on
    verify_one_finding and needs its own direct coverage, not just
    code-inspection against verify_session's twin logic."""
    from apps.core.engine.verification.verifier import verify_one_finding
    s = _session(); f = _finding(s, source="nuclei", sev="high")  # nuclei is active
    called = {"n": 0}

    def _verifier(finding):
        called["n"] += 1
        return Verdict(Verdict.VERIFIED)

    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"nuclei": _verifier}), \
         patch("apps.core.engine.verification.verifier._authorized_for", return_value=False):
        verdict = verify_one_finding(f)
    f.refresh_from_db()
    assert verdict.verdict == Verdict.INCONCLUSIVE
    assert f.verification_status == "inconclusive"
    assert called["n"] == 0  # never re-probed the target without authorization


@pytest.mark.django_db
def test_verify_one_finding_passive_authorized_verified_persists():
    """Happy path: a passive tool's verifier returning VERIFIED is called and
    the verdict is fully persisted (status + verified_at + extra.verification)."""
    from apps.core.engine.verification.verifier import verify_one_finding
    s = _session(); f = _finding(s, source="breach_check", sev="high")  # passive
    v = Verdict(Verdict.VERIFIED, evidence="still 3 breaches", detail="XposedOrNot")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: v}):
        verdict = verify_one_finding(f)
    f.refresh_from_db()
    assert verdict.verdict == Verdict.VERIFIED
    assert f.verification_status == "verified"
    assert f.verified_at is not None
    assert f.extra["verification"]["evidence"] == "still 3 breaches"
