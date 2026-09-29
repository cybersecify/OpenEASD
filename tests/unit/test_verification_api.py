import pytest
from unittest.mock import patch


@pytest.mark.django_db
def test_scan_verify_endpoint_409_when_running(auth_client):
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    r = auth_client.post(f"/api/scans/{s.uuid}/verify/", data={}, content_type="application/json")
    assert r.status_code == 409


@pytest.mark.django_db
def test_scan_verify_endpoint_runs_and_returns_counts(auth_client):
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding

    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    # Pre-set real verification_status values on a handful of findings so the
    # Count aggregation in the endpoint is actually exercised, not returning
    # an all-zero response that would pass even if the aggregation were wrong.
    # verify_session is mocked as a no-op so it doesn't overwrite these presets.
    Finding.objects.create(session=s, source="breach_check", check_type="a", severity="high",
                           title="t", target="example.com", verification_status="verified")
    Finding.objects.create(session=s, source="breach_check", check_type="b", severity="high",
                           title="t", target="example.com", verification_status="verified")
    Finding.objects.create(session=s, source="nuclei", check_type="c", severity="high",
                           title="t", target="example.com", verification_status="inconclusive")
    Finding.objects.create(session=s, source="subfinder", check_type="d", severity="high",
                           title="t", target="example.com", verification_status="unverified")

    with patch("apps.core.engine.scans.api.verify_session") as mock_v:
        r = auth_client.post(f"/api/scans/{s.uuid}/verify/", data={}, content_type="application/json")
    assert r.status_code == 200
    mock_v.assert_called_once()
    body = r.json()
    assert body == {"verified": 2, "inconclusive": 1, "unverified": 1}


@pytest.mark.django_db
def test_finding_verify_endpoint(auth_client):
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    from apps.core.engine.verification.verdict import Verdict

    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    # breach_check is a passive tool, so no DomainAuthorization is needed — the
    # test exercises verify_one_finding for real (only the registered tool
    # verifier is stubbed), so _apply's full persistence runs unmocked.
    f = Finding.objects.create(session=s, source="breach_check", check_type="missing_header",
                               severity="high", title="t", target="example.com")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: Verdict(Verdict.VERIFIED, evidence="absent")}):
        r = auth_client.post(f"/api/findings/{f.id}/verify/", data={}, content_type="application/json")
    assert r.status_code == 200
    body = r.json()
    assert body["verification_status"] == "verified"
    assert body["verified_at"] is not None
    assert body["verification"]["evidence"] == "absent"
    f.refresh_from_db()
    assert f.verification_status == "verified"
    assert f.verified_at is not None


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
