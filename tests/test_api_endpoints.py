"""
Smoke tests for all 35 Ninja API endpoints.

Verifies every endpoint:
  - Returns the expected HTTP status when authenticated
  - Returns 401 when called without a token (protected endpoints)
  - Response body contains the expected top-level keys

These are intentionally lightweight — they confirm the plumbing works, not
the full business logic (which is covered by unit tests elsewhere).
"""

import json
import pytest
from django.contrib.auth.models import User
from django.utils import timezone

from apps.core.api.auth import create_access_token, create_refresh_token
from apps.core.api.tokens.models import BlacklistedToken


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def post_json(client, path, data):
    return client.post(
        path,
        data=json.dumps(data),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def user(db):
    return User.objects.create_user(username="apitest", password="pass123")


@pytest.fixture
def auth_client(client, user):
    token = create_access_token(user.id)
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client


@pytest.fixture
def domain(db):
    from apps.core.domains.models import Domain
    return Domain.objects.create(name="smoke.example.com", is_active=True)


@pytest.fixture
def scan(db):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(
        domain="smoke.example.com", scan_type="full", status="completed",
        end_time=timezone.now(), total_findings=0,
    )


@pytest.fixture
def finding(db, scan):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=scan,
        source="domain_security",
        target="smoke.example.com",
        check_type="dns",
        severity="info",
        title="Smoke test finding",
        description="desc",
        remediation="none",
    )


@pytest.fixture
def workflow(db):
    from apps.core.workflows.models import Workflow
    return Workflow.objects.create(name="Smoke Workflow")


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class TestAuthLogin:
    def test_valid_credentials_returns_tokens(self, client, user):
        res = post_json(client, "/api/auth/login/", {"username": "apitest", "password": "pass123"})
        assert res.status_code == 200
        data = res.json()
        assert "access" in data
        assert "refresh" in data

    def test_invalid_credentials_returns_401(self, client, user):
        res = post_json(client, "/api/auth/login/", {"username": "apitest", "password": "wrong"})
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "UNAUTHORIZED"


class TestAuthLogout:
    def test_logout_blacklists_refresh_token(self, auth_client, user):
        refresh = create_refresh_token(user.id)
        res = post_json(auth_client, "/api/auth/logout/", {"refresh": refresh})
        assert res.status_code == 200
        assert res.json() == {"message": "logged out"}

    def test_logout_requires_auth(self, client, user):
        refresh = create_refresh_token(user.id)
        res = post_json(client, "/api/auth/logout/", {"refresh": refresh})
        assert res.status_code == 401


class TestAuthRefresh:
    def test_valid_refresh_returns_new_access(self, client, user):
        refresh = create_refresh_token(user.id)
        res = post_json(client, "/api/auth/refresh/", {"refresh": refresh})
        assert res.status_code == 200
        assert "access" in res.json()

    def test_blacklisted_refresh_returns_401(self, client, user):
        import jwt as pyjwt
        from django.conf import settings

        refresh = create_refresh_token(user.id)
        payload = pyjwt.decode(refresh, settings.SECRET_KEY, algorithms=["HS256"])
        BlacklistedToken.objects.create(
            jti=payload["jti"],
            expires_at=timezone.now() + timezone.timedelta(days=7),
        )
        res = post_json(client, "/api/auth/refresh/", {"refresh": refresh})
        assert res.status_code == 401

    def test_invalid_refresh_returns_401(self, client):
        res = post_json(client, "/api/auth/refresh/", {"refresh": "not.a.token"})
        assert res.status_code == 401


class TestAuthUser:
    def test_returns_current_user(self, auth_client, user):
        res = auth_client.get("/api/auth/user/")
        assert res.status_code == 200
        data = res.json()
        assert data["username"] == "apitest"
        assert "id" in data

    def test_requires_auth(self, client):
        res = client.get("/api/auth/user/")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class TestDashboard:
    def test_returns_kpis(self, auth_client, db):
        res = auth_client.get("/api/dashboard/")
        assert res.status_code == 200
        data = res.json()
        assert "kpi_critical" in data
        assert "kpi_high" in data

    def test_requires_auth(self, client):
        res = client.get("/api/dashboard/")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

class TestDomainsList:
    def test_returns_list(self, auth_client, domain):
        res = auth_client.get("/api/domains/")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        assert any(d["name"] == "smoke.example.com" for d in data)

    def test_requires_auth(self, client):
        assert client.get("/api/domains/").status_code == 401


class TestDomainsCreate:
    def test_creates_domain(self, auth_client, db):
        res = post_json(auth_client, "/api/domains/", {"name": "new.example.com"})
        assert res.status_code == 201
        assert res.json()["name"] == "new.example.com"

    def test_duplicate_returns_400(self, auth_client, domain):
        res = post_json(auth_client, "/api/domains/", {"name": "smoke.example.com"})
        assert res.status_code == 400

    def test_requires_auth(self, client):
        assert post_json(client, "/api/domains/", {"name": "x.com"}).status_code == 401


class TestDomainsToggle:
    def test_toggles_active(self, auth_client, domain):
        original = domain.is_active
        res = post_json(auth_client, f"/api/domains/{domain.pk}/toggle/", {})
        assert res.status_code == 200
        assert res.json()["is_active"] != original

    def test_requires_auth(self, client, domain):
        assert post_json(client, f"/api/domains/{domain.pk}/toggle/", {}).status_code == 401

    def test_not_found(self, auth_client):
        assert post_json(auth_client, "/api/domains/99999/toggle/", {}).status_code == 404


class TestDomainsDelete:
    def test_deletes_domain(self, auth_client, domain):
        res = post_json(auth_client, f"/api/domains/{domain.pk}/delete/", {})
        assert res.status_code == 200
        assert res.json()["deleted"] == "smoke.example.com"

    def test_requires_auth(self, client, domain):
        assert post_json(client, f"/api/domains/{domain.pk}/delete/", {}).status_code == 401


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

class TestScansList:
    def test_returns_paginated(self, auth_client, scan):
        res = auth_client.get("/api/scans/")
        assert res.status_code == 200
        data = res.json()
        assert "results" in data
        assert "total" in data
        assert "page" in data

    def test_filter_by_domain(self, auth_client, scan):
        res = auth_client.get("/api/scans/?domain=smoke")
        assert res.status_code == 200
        assert all("smoke" in s["domain_name"] for s in res.json()["results"])

    def test_filter_by_status(self, auth_client, scan):
        res = auth_client.get("/api/scans/?status=completed")
        assert res.status_code == 200
        assert all(s["status"] == "completed" for s in res.json()["results"])

    def test_requires_auth(self, client):
        assert client.get("/api/scans/").status_code == 401


class TestScansStart:
    def test_start_scan_now(self, auth_client, domain):
        from unittest.mock import patch
        fake_session = type("S", (), {"uuid": "test-uuid-1234", "id": 1})()
        with patch("apps.core.scans.tasks.run_scan_task"), \
             patch("apps.core.scans.pipeline.create_scan_session", return_value=fake_session):
            res = post_json(auth_client, "/api/scans/start/", {"domain": "smoke.example.com", "schedule_type": "now"})
        assert res.status_code == 201
        assert "uuid" in res.json()

    def test_missing_domain_returns_400(self, auth_client):
        res = post_json(auth_client, "/api/scans/start/", {"domain": "", "schedule_type": "now"})
        assert res.status_code == 400

    def test_requires_auth(self, client):
        assert post_json(client, "/api/scans/start/", {"domain": "x.com"}).status_code == 401


class TestScanDetail:
    def test_returns_session_and_assets(self, auth_client, scan):
        res = auth_client.get(f"/api/scans/{scan.uuid}/")
        assert res.status_code == 200
        data = res.json()
        assert "session" in data
        assert "vuln_counts" in data
        assert "subdomains" in data

    def test_not_found(self, auth_client):
        assert auth_client.get("/api/scans/00000000-0000-0000-0000-000000000000/").status_code == 404

    def test_requires_auth(self, client, scan):
        assert client.get(f"/api/scans/{scan.uuid}/").status_code == 401


class TestScanStatus:
    def test_returns_status(self, auth_client, scan):
        res = auth_client.get(f"/api/scans/{scan.uuid}/status/")
        assert res.status_code == 200
        data = res.json()
        assert data["session"]["status"] == "completed"
        assert "vuln_counts" in data
        assert "asset_counts" in data

    def test_requires_auth(self, client, scan):
        assert client.get(f"/api/scans/{scan.uuid}/status/").status_code == 401


class TestScanStop:
    def test_cancels_running_scan(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        running = ScanSession.objects.create(
            domain="smoke.example.com", scan_type="full", status="running"
        )
        res = post_json(auth_client, f"/api/scans/{running.uuid}/stop/", {})
        assert res.status_code == 200
        assert res.json()["status"] == "cancelled"

    def test_requires_auth(self, client, scan):
        assert post_json(client, f"/api/scans/{scan.uuid}/stop/", {}).status_code == 401


class TestScanDelete:
    def test_deletes_scan(self, auth_client, scan):
        uuid = str(scan.uuid)
        res = post_json(auth_client, f"/api/scans/{uuid}/delete/", {})
        assert res.status_code == 200
        assert res.json()["deleted"] == uuid

    def test_requires_auth(self, client, scan):
        assert post_json(client, f"/api/scans/{scan.uuid}/delete/", {}).status_code == 401


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class TestFindingsList:
    def test_returns_paginated_findings(self, auth_client, finding):
        res = auth_client.get("/api/scans/findings/")
        assert res.status_code == 200
        data = res.json()
        assert "findings" in data
        assert "counts" in data
        assert "total" in data

    def test_filter_by_severity(self, auth_client, finding):
        res = auth_client.get("/api/scans/findings/?severity=info")
        assert res.status_code == 200

    def test_requires_auth(self, client):
        assert client.get("/api/scans/findings/").status_code == 401


class TestFindingStatusUpdate:
    def test_updates_status(self, auth_client, finding):
        res = post_json(
            auth_client,
            f"/api/scans/findings/{finding.id}/status/",
            {"status": "acknowledged"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "acknowledged"

    def test_resolved_sets_resolved_at(self, auth_client, finding):
        res = post_json(
            auth_client,
            f"/api/scans/findings/{finding.id}/status/",
            {"status": "resolved", "resolution_note": "Fixed"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "resolved"
        assert data["resolved_at"] is not None

    def test_invalid_status_returns_400(self, auth_client, finding):
        res = post_json(
            auth_client,
            f"/api/scans/findings/{finding.id}/status/",
            {"status": "invalid_status"},
        )
        assert res.status_code == 400

    def test_requires_auth(self, client, finding):
        assert post_json(client, f"/api/scans/findings/{finding.id}/status/", {"status": "open"}).status_code == 401


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

class TestUrlsList:
    def test_returns_paginated(self, auth_client, db):
        res = auth_client.get("/api/scans/urls/")
        assert res.status_code == 200
        data = res.json()
        assert "results" in data
        assert "total" in data

    def test_requires_auth(self, client):
        assert client.get("/api/scans/urls/").status_code == 401


# ---------------------------------------------------------------------------
# Scheduled jobs
# ---------------------------------------------------------------------------

class TestScheduledList:
    def test_returns_list(self, auth_client):
        res = auth_client.get("/api/scheduled/")
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_requires_auth(self, client):
        assert client.get("/api/scheduled/").status_code == 401


class TestScheduledCancel:
    def test_invalid_job_id_returns_400(self, auth_client):
        res = post_json(auth_client, "/api/scheduled/bad_id/cancel/", {})
        assert res.status_code == 400

    def test_unknown_once_job_returns_note(self, auth_client):
        res = post_json(auth_client, "/api/scheduled/once_nonexistent/cancel/", {})
        assert res.status_code == 200
        data = res.json()
        assert data["cancelled"] == "once_nonexistent"
        assert "note" in data  # already completed/cancelled

    def test_requires_auth(self, client):
        assert post_json(client, "/api/scheduled/once_xyz/cancel/", {}).status_code == 401


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------

class TestWorkflowTools:
    def test_returns_tools_list(self, auth_client):
        res = auth_client.get("/api/workflows/tools/")
        assert res.status_code == 200
        data = res.json()
        assert "tools" in data
        assert "requires" in data

    def test_requires_auth(self, client):
        assert client.get("/api/workflows/tools/").status_code == 401


class TestWorkflowsList:
    def test_returns_list(self, auth_client, workflow):
        res = auth_client.get("/api/workflows/")
        assert res.status_code == 200
        workflows = res.json()
        assert isinstance(workflows, list)
        assert any(w["name"] == "Smoke Workflow" for w in workflows)

    def test_requires_auth(self, client):
        assert client.get("/api/workflows/").status_code == 401


class TestWorkflowCreate:
    def test_creates_workflow(self, auth_client, db):
        res = post_json(
            auth_client,
            "/api/workflows/create/",
            {"name": "Test Workflow", "tools": ["subfinder"]},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["name"] == "Test Workflow"
        assert len(data["steps"]) == 1

    def test_empty_name_returns_400(self, auth_client, db):
        res = post_json(auth_client, "/api/workflows/create/", {"name": ""})
        assert res.status_code == 400

    def test_unknown_tool_returns_400(self, auth_client, db):
        res = post_json(auth_client, "/api/workflows/create/", {"name": "W", "tools": ["fake_tool"]})
        assert res.status_code == 400

    def test_requires_auth(self, client):
        assert post_json(client, "/api/workflows/create/", {"name": "W"}).status_code == 401


class TestWorkflowDetail:
    def test_returns_workflow_and_steps(self, auth_client, workflow):
        res = auth_client.get(f"/api/workflows/{workflow.pk}/")
        assert res.status_code == 200
        data = res.json()
        assert "workflow" in data
        assert "tool_steps" in data
        assert data["workflow"]["name"] == "Smoke Workflow"

    def test_not_found(self, auth_client):
        assert auth_client.get("/api/workflows/99999/").status_code == 404

    def test_requires_auth(self, client, workflow):
        assert client.get(f"/api/workflows/{workflow.pk}/").status_code == 401


class TestWorkflowUpdate:
    def test_updates_name(self, auth_client, workflow):
        res = post_json(
            auth_client,
            f"/api/workflows/{workflow.pk}/update/",
            {"name": "Updated Name", "tools": []},
        )
        assert res.status_code == 200
        assert res.json()["name"] == "Updated Name"

    def test_requires_auth(self, client, workflow):
        assert post_json(client, f"/api/workflows/{workflow.pk}/update/", {"name": "X"}).status_code == 401


class TestWorkflowDelete:
    def test_deletes_workflow(self, auth_client, workflow):
        res = post_json(auth_client, f"/api/workflows/{workflow.pk}/delete/", {})
        assert res.status_code == 200
        assert res.json()["deleted"] == "Smoke Workflow"

    def test_requires_auth(self, client, workflow):
        assert post_json(client, f"/api/workflows/{workflow.pk}/delete/", {}).status_code == 401


class TestWorkflowStepToggle:
    def test_toggles_step(self, auth_client, workflow):
        res = post_json(auth_client, f"/api/workflows/{workflow.pk}/steps/subfinder/toggle/", {})
        assert res.status_code == 200
        data = res.json()
        assert data["tool"] == "subfinder"
        assert isinstance(data["enabled"], bool)

    def test_toggle_twice_returns_original(self, auth_client, workflow):
        url = f"/api/workflows/{workflow.pk}/steps/subfinder/toggle/"
        first = post_json(auth_client, url, {}).json()["enabled"]
        second = post_json(auth_client, url, {}).json()["enabled"]
        assert first != second

    def test_requires_auth(self, client, workflow):
        assert post_json(client, f"/api/workflows/{workflow.pk}/steps/subfinder/toggle/", {}).status_code == 401


# ---------------------------------------------------------------------------
# Insights
# ---------------------------------------------------------------------------

class TestInsights:
    def test_returns_insights(self, auth_client, scan_summary):
        res = auth_client.get("/api/insights/")
        assert res.status_code == 200
        data = res.json()
        assert "kpi_open_critical" in data
        assert "kpi_open_high" in data
        assert "chart_data" in data

    def test_requires_auth(self, client):
        assert client.get("/api/insights/").status_code == 401


@pytest.fixture
def scan_summary(db, scan):
    from apps.core.insights.models import ScanSummary
    return ScanSummary.objects.create(
        session=scan,
        domain="smoke.example.com",
        scan_date=scan.end_time,
        critical_count=0, high_count=1, medium_count=0, low_count=0,
        total_findings=1, new_exposures=1, removed_exposures=0,
        tool_breakdown={},
    )
