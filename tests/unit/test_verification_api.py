import pytest


@pytest.mark.django_db
def test_findings_api_exposes_verification(auth_client):
    from apps.core.data.domains.models import Domain
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    Domain.objects.get_or_create(name="example.com")
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                           severity="high", title="t", target="example.com",
                           verification_status="verified",
                           extra={"verification": {"verdict": "verified", "evidence": "absent"}})
    row = auth_client.get("/api/findings/?domain=example.com").json()["findings"][0]
    assert row["verification_status"] == "verified"
    assert row["verification"]["evidence"] == "absent"


@pytest.mark.django_db
def test_issues_api_exposes_verification(auth_client):
    from apps.core.data.domains.models import Domain
    from apps.core.data.issues.models import Issue, issue_key
    from django.utils import timezone
    d, _ = Domain.objects.get_or_create(name="example.com")
    now = timezone.now()
    Issue.objects.create(domain=d, source="web_checker", check_type="missing_header",
                         check_id="web_checker:missing_header",
                         key=issue_key("web_checker:missing_header", "example.com"),
                         title="t", target="example.com", severity="high", status="open",
                         first_seen=now, last_seen=now, verification_status="verified")
    row = auth_client.get("/api/issues/?status=").json()["issues"][0]
    assert row["verification_status"] == "verified"
