import pytest
from unittest.mock import patch


@pytest.mark.django_db
def test_finalize_calls_verify_before_issue_rollup(settings):
    settings.FINDING_VERIFICATION_ENABLED = True
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    order = []
    with patch.object(pipeline, "verify_session", side_effect=lambda *a, **k: order.append("verify")), \
         patch("apps.core.data.issues.rollup.rollup_session_issues", side_effect=lambda *a, **k: order.append("issues")):
        pipeline._finalize_session(s)
    assert order == ["verify", "issues"]


@pytest.mark.django_db
def test_finalize_skips_verify_when_disabled(settings):
    settings.FINDING_VERIFICATION_ENABLED = False
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    with patch.object(pipeline, "verify_session") as mock_verify:
        pipeline._finalize_session(s)
    mock_verify.assert_not_called()


@pytest.mark.django_db
def test_disabled_leaves_findings_unverified(settings):
    """Regression lock: with the flag off, finalize never touches verification
    fields — a finding created during a disabled scan stays "unverified", not
    just "verify_session wasn't called" (Task 6 gates this; this asserts the
    observable outcome end-to-end through the real Finding row)."""
    settings.FINDING_VERIFICATION_ENABLED = False
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    f = Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                               severity="high", title="t", target="example.com")
    pipeline._finalize_session(s)
    f.refresh_from_db()
    assert f.verification_status == "unverified"  # untouched when disabled


@pytest.mark.django_db
def test_verify_error_does_not_fail_finalize(settings):
    settings.FINDING_VERIFICATION_ENABLED = True
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    with patch.object(pipeline, "verify_session", side_effect=RuntimeError("boom")):
        pipeline._finalize_session(s)  # must not raise
    s.refresh_from_db()
    assert s.status in ("completed", "partial")
