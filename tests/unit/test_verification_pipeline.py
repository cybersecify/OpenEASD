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
def test_verify_error_does_not_fail_finalize(settings):
    settings.FINDING_VERIFICATION_ENABLED = True
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    with patch.object(pipeline, "verify_session", side_effect=RuntimeError("boom")):
        pipeline._finalize_session(s)  # must not raise
    s.refresh_from_db()
    assert s.status in ("completed", "partial")
