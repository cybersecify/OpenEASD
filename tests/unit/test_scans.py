"""Unit tests for apps/scans — model and views."""

import uuid
import pytest
from django.urls import reverse


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanSessionModel:
    def test_uuid_generated_on_create(self, scan_session):
        assert scan_session.uuid is not None
        assert isinstance(scan_session.uuid, uuid.UUID)

    def test_uuid_unique_per_session(self, db):
        from apps.scans.models import ScanSession
        s1 = ScanSession.objects.create(domain="a.com", scan_type="full")
        s2 = ScanSession.objects.create(domain="b.com", scan_type="full")
        assert s1.uuid != s2.uuid

    def test_default_status_is_pending(self, db):
        from apps.scans.models import ScanSession
        s = ScanSession.objects.create(domain="test.com", scan_type="full")
        assert s.status == "pending"

    def test_str_representation(self, scan_session):
        s = str(scan_session)
        assert "example.com" in s


@pytest.mark.django_db
class TestScanDeltaModel:
    def test_create_delta(self, completed_session):
        from apps.scans.models import ScanDelta
        delta = ScanDelta.objects.create(
            session=completed_session,
            change_type="new",
            change_category="domain_finding",
            item_identifier="dns:No MX records found",
        )
        assert delta.change_type == "new"
        assert delta.session == completed_session

    def test_delta_cascades_on_session_delete(self, completed_session):
        from apps.scans.models import ScanDelta
        ScanDelta.objects.create(
            session=completed_session,
            change_type="new",
            change_category="domain_finding",
            item_identifier="test",
        )
        session_id = completed_session.id
        completed_session.delete()
        assert not ScanDelta.objects.filter(session_id=session_id).exists()


# ---------------------------------------------------------------------------
# View tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanViews:
    def test_scan_list_requires_login(self, client):
        resp = client.get(reverse("scan-list"))
        assert resp.status_code == 302

    def test_scan_list_authenticated(self, auth_client, completed_session):
        resp = auth_client.get(reverse("scan-list"))
        assert resp.status_code == 200

    def test_scan_detail_uses_uuid(self, auth_client, completed_session):
        url = reverse("scan-detail", args=[completed_session.uuid])
        resp = auth_client.get(url)
        assert resp.status_code == 200

    def test_scan_detail_invalid_uuid_returns_404(self, auth_client):
        url = reverse("scan-detail", args=[uuid.uuid4()])
        resp = auth_client.get(url)
        assert resp.status_code == 404

    def test_scan_start_get(self, auth_client):
        resp = auth_client.get(reverse("scan-start"))
        assert resp.status_code == 200
        assert b"Start Scan" in resp.content

    def test_scan_start_prefills_domain(self, auth_client):
        resp = auth_client.get(reverse("scan-start") + "?domain=test.com")
        assert b"test.com" in resp.content

    def test_scan_list_filter_by_domain(self, auth_client, completed_session):
        resp = auth_client.get(reverse("scan-list") + "?domain=example")
        assert resp.status_code == 200
        assert b"example.com" in resp.content

    def test_scan_list_filter_no_match(self, auth_client, completed_session):
        resp = auth_client.get(reverse("scan-list") + "?domain=notexist")
        assert resp.status_code == 200
        assert b"example.com" not in resp.content

    def test_vulnerability_list_requires_login(self, client):
        resp = client.get(reverse("vulnerability-list"))
        assert resp.status_code == 302

    def test_vulnerability_list_authenticated(self, auth_client, domain_finding):
        resp = auth_client.get(reverse("vulnerability-list"))
        assert resp.status_code == 200
        assert b"No MX records found" in resp.content

    def test_vulnerability_list_filter_by_severity(self, auth_client, domain_finding):
        resp = auth_client.get(reverse("vulnerability-list") + "?severity=high")
        assert resp.status_code == 200
        assert b"No MX records found" in resp.content

        resp = auth_client.get(reverse("vulnerability-list") + "?severity=critical")
        assert resp.status_code == 200
        assert b"No MX records found" not in resp.content
