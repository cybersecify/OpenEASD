import pytest
from django.contrib.auth.models import User


@pytest.fixture(autouse=True)
def _plain_staticfiles(settings):
    # The prod manifest storage needs collectstatic; tests render {% static %}.
    settings.STORAGES = {
        **settings.STORAGES,
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }


@pytest.mark.django_db
class TestAuthShell:
    def test_dashboard_requires_login(self, client):
        resp = client.get("/app/")
        assert resp.status_code == 302 and "/login/" in resp["Location"]

    def test_dashboard_renders_when_logged_in(self, client):
        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        assert client.get("/app/").status_code == 200


@pytest.mark.django_db
class TestDashboard:
    def _login(self, client):
        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")

    def test_dashboard_shows_domain_and_severity_counts(self, client):
        from apps.core.data.domains.models import Domain
        from apps.core.data.findings.models import Finding
        from apps.core.engine.scans.models import ScanSession

        Domain.objects.create(name="example.com")
        s = ScanSession.objects.create(domain="example.com", status="completed")
        Finding.objects.create(session=s, source="nuclei", severity="high", title="Bad thing", target="example.com")
        Finding.objects.create(session=s, source="nuclei", severity="medium", title="Meh", target="example.com")
        self._login(client)
        resp = client.get("/app/")
        assert resp.status_code == 200
        body = resp.content.decode()
        assert "example.com" in body
        assert "1 high" in body and "1 medium" in body
        assert "Bad thing" in body

    def test_activity_partial_ok(self, client):
        self._login(client)
        assert client.get("/app/activity/").status_code == 200


@pytest.mark.django_db
class TestDomains:
    @pytest.fixture(autouse=True)
    def _login(self, client):
        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")

    def test_list_renders(self, client):
        from apps.core.data.domains.models import Domain

        Domain.objects.create(name="example.com")
        resp = client.get("/app/domains/")
        assert resp.status_code == 200 and b"example.com" in resp.content

    def test_add_domain(self, client):
        from apps.core.data.domains.models import Domain

        resp = client.post("/app/domains/add/", {"name": "Example.com"})
        assert resp.status_code == 302
        assert Domain.objects.filter(name="example.com").exists()
        assert client.get("/app/domains/example.com/").status_code == 200

    def test_non_apex_rejected(self, client):
        from apps.core.data.domains.models import Domain

        resp = client.post("/app/domains/add/", {"name": "sub.example.com"}, follow=True)
        assert not Domain.objects.exists()
        assert "subdomain" in resp.content.decode()

    def test_authorize_requires_attestation(self, client):
        from apps.core.data.domains.models import Domain, DomainAuthorization

        Domain.objects.create(name="example.com")
        client.post("/app/domains/example.com/authorize/", {})
        assert not DomainAuthorization.is_authorized("example.com")
        client.post("/app/domains/example.com/authorize/", {"attestation": "1"})
        assert DomainAuthorization.is_authorized("example.com")

    def test_monitoring_sets_and_clears(self, client):
        from apps.core.data.domains.models import Domain

        Domain.objects.create(name="example.com")
        client.post("/app/domains/example.com/monitoring/", {"interval_hours": "24"})
        assert Domain.objects.get(name="example.com").monitoring_interval_hours == 24
        client.post("/app/domains/example.com/monitoring/", {"interval_hours": ""})
        assert Domain.objects.get(name="example.com").monitoring_interval_hours is None

    def test_delete_requires_confirm(self, client):
        from apps.core.data.domains.models import Domain

        Domain.objects.create(name="example.com")
        client.post("/app/domains/example.com/delete/", {"confirm": "nope"})
        assert Domain.objects.filter(name="example.com").exists()
        client.post("/app/domains/example.com/delete/", {"confirm": "example.com"})
        assert not Domain.objects.exists()


@pytest.mark.django_db
class TestScanStart:
    @pytest.fixture(autouse=True)
    def _login(self, client):
        from apps.core.data.domains.models import Domain

        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        Domain.objects.create(name="example.com")

    def _wf(self, name):
        from apps.core.engine.workflows.models import Workflow

        return Workflow.objects.get(name=name)

    def test_passive_mode_bypasses_authorization(self, client):
        from unittest.mock import patch

        from apps.core.engine.scans.models import ScanSession

        wf = self._wf("Passive Scan Deep")
        with patch("apps.mvp.views.run_scan_task") as task:
            resp = client.post("/app/scan/start/", {"domain": "example.com", "workflow_id": wf.id})
        assert resp.status_code == 302
        assert ScanSession.objects.filter(domain="example.com").count() == 1
        task.assert_called_once()

    def test_active_mode_requires_authorization(self, client):
        from unittest.mock import patch

        from apps.core.data.domains.models import Domain, DomainAuthorization
        from apps.core.engine.scans.models import ScanSession

        wf = self._wf("Full Scan")
        with patch("apps.mvp.views.run_scan_task") as task:
            resp = client.post("/app/scan/start/", {"domain": "example.com", "workflow_id": wf.id}, follow=True)
            assert not ScanSession.objects.exists()
            task.assert_not_called()
            assert b"must be authorized" in resp.content
            DomainAuthorization.objects.create(
                domain=Domain.objects.get(name="example.com"), auth_type="owner",
                authorized_at="2026-01-01", authorized_by="admin")
            client.post("/app/scan/start/", {"domain": "example.com", "workflow_id": wf.id})
        assert ScanSession.objects.count() == 1
        task.assert_called_once()

    def test_unknown_workflow_rejected(self, client):
        from unittest.mock import patch

        with patch("apps.mvp.views.run_scan_task") as task:
            resp = client.post("/app/scan/start/", {"domain": "example.com", "workflow_id": "999999"})
        assert resp.status_code == 302
        task.assert_not_called()

    def test_detail_renders_modes(self, client):
        resp = client.get("/app/domains/example.com/")
        assert b"Passive Scan Deep" in resp.content and b"authorize first" in resp.content


@pytest.mark.django_db
class TestScanDetail:
    @pytest.fixture(autouse=True)
    def _seed(self, client):
        from apps.core.data.findings.models import Finding
        from apps.core.engine.scans.models import ScanSession
        from apps.core.engine.workflows.models import WorkflowRun, WorkflowStepResult

        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        self.s = ScanSession.objects.create(domain="example.com", status="running")
        run = WorkflowRun.objects.create(session=self.s, status="running")
        WorkflowStepResult.objects.create(run=run, tool="subfinder", status="completed", order=1)
        WorkflowStepResult.objects.create(run=run, tool="nuclei", status="failed", order=2, error="boom")
        Finding.objects.create(session=self.s, source="nuclei", severity="high", title="High thing", target="a.example.com")
        Finding.objects.create(session=self.s, source="nuclei", severity="low", title="Low thing", target="a.example.com")

    def test_detail_shows_finding_and_step(self, client):
        resp = client.get(f"/app/scan/{self.s.uuid}/")
        body = resp.content.decode()
        assert resp.status_code == 200
        assert "High thing" in body and "subfinder" in body
        assert "every 3s" in body

    def test_terminal_detail_has_no_poll_trigger(self, client):
        self.s.status = "completed"
        self.s.save()
        assert "every 3s" not in client.get(f"/app/scan/{self.s.uuid}/").content.decode()

    def test_progress_partial(self, client):
        resp = client.get(f"/app/scan/{self.s.uuid}/progress/")
        body = resp.content.decode()
        assert resp.status_code == 200
        assert "nuclei" in body and "Failed:" in body and "1 high" in body

    def test_progress_terminal_refreshes(self, client):
        self.s.status = "completed"
        self.s.save()
        resp = client.get(f"/app/scan/{self.s.uuid}/progress/")
        assert resp.status_code == 204 and resp["HX-Refresh"] == "true"

    def test_cancel_flips_status(self, client):
        from unittest.mock import patch

        with patch("apps.core.engine.scheduler.scheduler._cancel_workflows_for_sessions") as c:
            resp = client.post(f"/app/scan/{self.s.uuid}/cancel/")
        assert resp.status_code == 302
        self.s.refresh_from_db()
        assert self.s.status == "cancelled" and self.s.end_time
        c.assert_called_once_with([self.s.id])

    def test_sev_filter(self, client):
        body = client.get(f"/app/scan/{self.s.uuid}/?sev=high").content.decode()
        assert "High thing" in body and "Low thing" not in body
