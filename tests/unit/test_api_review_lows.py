"""Tests for the API-review LOW fixes:
- L-a: /api/findings/ counts respect the domain/source filters (not whole-fleet).
- L-b: workflow_id on a scheduled scan → 400 (not silently dropped).
- enum validation: /api/scans/?status= and /api/changes/?change_type= → 400 on unknown.
"""

import pytest
from django.contrib.auth.models import User
from django.test import Client
from ninja_jwt.tokens import AccessToken

from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession

pytestmark = pytest.mark.django_db


@pytest.fixture
def auth(db):
    u = User.objects.create_user(username="admin", password="longpass1")
    return {"HTTP_AUTHORIZATION": f"Bearer {AccessToken.for_user(u)}"}


def _open_crit(domain):
    s = ScanSession.objects.create(domain=domain, status="completed")
    Finding.objects.create(
        session=s, source="nmap", check_type="cve", severity="critical",
        status="open", title="t", description="d", remediation="r", target="x",
    )
    return s


# --- L-a: findings counts scoped to the filter -------------------------------

class TestFindingsCountsScoped:
    def test_counts_respect_domain_filter(self, auth):
        _open_crit("a.com")
        _open_crit("b.com")
        # unfiltered: counts see both domains' latest sessions
        allc = Client().get("/api/findings/", **auth).json()["counts"]
        assert allc["open_critical"] == 2
        # filtered by domain: counts reflect only that domain (was the bug — showed 2)
        ac = Client().get("/api/findings/?domain=a.com", **auth).json()["counts"]
        assert ac["open_critical"] == 1


# --- L-b: workflow_id rejected on scheduled scans ----------------------------

class TestScheduledWorkflowIdRejected:
    def test_workflow_id_on_scheduled_returns_400(self, auth):
        resp = Client().post(
            "/api/scans/start/",
            data='{"domain":"ex.com","schedule_type":"once","scheduled_at":"2099-01-01T00:00:00","workflow_id":1}',
            content_type="application/json", **auth,
        )
        assert resp.status_code == 400
        assert "workflow_id" in resp.json()["error"]["message"]


# --- enum validation ---------------------------------------------------------

class TestFilterEnumValidation:
    def test_list_scans_bad_status_400(self, auth):
        resp = Client().get("/api/scans/?status=bogus", **auth)
        assert resp.status_code == 400
        assert "status" in resp.json()["error"]["message"]

    def test_list_scans_valid_status_200(self, auth):
        assert Client().get("/api/scans/?status=completed", **auth).status_code == 200

    def test_list_changes_bad_change_type_400(self, auth):
        resp = Client().get("/api/changes/?change_type=bogus", **auth)
        assert resp.status_code == 400
        assert "change_type" in resp.json()["error"]["message"]

    def test_list_changes_valid_change_type_200(self, auth):
        assert Client().get("/api/changes/?change_type=new", **auth).status_code == 200
