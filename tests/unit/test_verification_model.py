import pytest


@pytest.mark.django_db
def test_finding_defaults_to_unverified():
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                               severity="medium", title="Missing CSP", target="example.com")
    assert f.verification_status == "unverified"
    assert f.verified_at is None
