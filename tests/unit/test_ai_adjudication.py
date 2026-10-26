import pytest
from unittest.mock import patch


def _finding(s, status="verified", severity="high"):
    from apps.core.data.findings.models import Finding
    return Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                                  severity=severity, title="t", target="example.com",
                                  verification_status=status,
                                  extra={"verification": {"verdict": status, "evidence": "x"}})


@pytest.mark.django_db
def test_noop_when_ai_inactive():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = _finding(s)
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=False), \
         patch("apps.core.console.ai.adjudicate._adjudicate_one") as mocked:
        run_adjudication(s)
    f.refresh_from_db()
    assert "ai" not in f.extra["verification"]
    mocked.assert_not_called()


@pytest.mark.django_db
def test_annotates_but_never_flips_verdict_when_active():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = _finding(s, status="verified")
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=True), \
         patch("apps.core.console.ai.adjudicate._adjudicate_one",
               return_value={"confidence": 0.9, "rationale": "clear"}):
        run_adjudication(s)
    f.refresh_from_db()
    assert f.verification_status == "verified"           # unchanged
    assert f.extra["verification"]["ai"]["confidence"] == 0.9
    assert f.extra["verification"]["ai"]["rationale"] == "clear"
    assert f.extra["verification"]["verdict"] == "verified"  # deterministic verdict untouched


@pytest.mark.django_db
def test_ai_failure_is_swallowed():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = _finding(s)
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=True), \
         patch("apps.core.console.ai.adjudicate._adjudicate_one", side_effect=RuntimeError("cf down")):
        run_adjudication(s)  # must not raise
    f.refresh_from_db()
    assert "ai" not in f.extra["verification"]


@pytest.mark.django_db
def test_skips_low_severity_and_unverified_findings():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    low = _finding(s, status="verified", severity="low")
    unverified = _finding(s, status="unverified", severity="critical")
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=True), \
         patch("apps.core.console.ai.adjudicate._adjudicate_one") as mocked:
        run_adjudication(s)
    mocked.assert_not_called()
    low.refresh_from_db()
    unverified.refresh_from_db()
    assert "ai" not in low.extra["verification"]
    assert "ai" not in unverified.extra["verification"]


@pytest.mark.django_db
def test_returns_none_from_model_is_skipped_without_error():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = _finding(s, status="inconclusive", severity="medium")
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=True), \
         patch("apps.core.console.ai.adjudicate._adjudicate_one", return_value=None):
        run_adjudication(s)
    f.refresh_from_db()
    assert "ai" not in f.extra["verification"]
