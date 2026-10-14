import re

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
        resp = client.get("/")
        assert resp.status_code == 302 and resp["Location"].startswith("/login/")

    def test_dashboard_renders_when_logged_in(self, client):
        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        assert client.get("/").status_code == 200


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
        resp = client.get("/")
        assert resp.status_code == 200
        body = resp.content.decode()
        assert re.search(r"example\.com", body)   # regex, not a substring-in-URL check (CodeQL FP)
        assert "1 high" in body and "1 medium" in body
        assert "Bad thing" in body

    def test_activity_partial_ok(self, client):
        self._login(client)
        assert client.get("/activity/").status_code == 200


@pytest.mark.django_db
class TestDomains:
    @pytest.fixture(autouse=True)
    def _login(self, client):
        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")

    def test_list_renders(self, client):
        from apps.core.data.domains.models import Domain

        Domain.objects.create(name="example.com")
        resp = client.get("/domains/")
        assert resp.status_code == 200 and re.search(rb"example\.com", resp.content)

    def test_add_domain(self, client):
        from apps.core.data.domains.models import Domain

        resp = client.post("/domains/add/", {"name": "Example.com"})
        assert resp.status_code == 302
        assert Domain.objects.filter(name="example.com").exists()
        assert client.get("/domains/example.com/").status_code == 200

    def test_non_apex_rejected(self, client):
        from apps.core.data.domains.models import Domain

        resp = client.post("/domains/add/", {"name": "sub.example.com"}, follow=True)
        assert not Domain.objects.exists()
        assert "subdomain" in resp.content.decode()

    def test_authorize_requires_attestation(self, client):
        from apps.core.data.domains.models import Domain, DomainAuthorization

        Domain.objects.create(name="example.com")
        client.post("/domains/example.com/authorize/", {})
        assert not DomainAuthorization.is_authorized("example.com")
        client.post("/domains/example.com/authorize/", {"attestation": "1"})
        assert DomainAuthorization.is_authorized("example.com")

    def test_monitoring_sets_and_clears(self, client):
        from apps.core.data.domains.models import Domain

        Domain.objects.create(name="example.com")
        client.post("/domains/example.com/monitoring/", {"interval_hours": "24"})
        assert Domain.objects.get(name="example.com").monitoring_interval_hours == 24
        client.post("/domains/example.com/monitoring/", {"interval_hours": ""})
        assert Domain.objects.get(name="example.com").monitoring_interval_hours is None

    def test_delete_requires_confirm(self, client):
        from apps.core.data.domains.models import Domain

        Domain.objects.create(name="example.com")
        client.post("/domains/example.com/delete/", {"confirm": "nope"})
        assert Domain.objects.filter(name="example.com").exists()
        client.post("/domains/example.com/delete/", {"confirm": "example.com"})
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
            resp = client.post("/scan/start/", {"domain": "example.com", "workflow_id": wf.id})
        assert resp.status_code == 302
        assert ScanSession.objects.filter(domain="example.com").count() == 1
        task.assert_called_once()

    def test_active_mode_requires_authorization(self, client):
        from unittest.mock import patch

        from apps.core.data.domains.models import Domain, DomainAuthorization
        from apps.core.engine.scans.models import ScanSession

        wf = self._wf("Full Scan")
        with patch("apps.mvp.views.run_scan_task") as task:
            resp = client.post("/scan/start/", {"domain": "example.com", "workflow_id": wf.id}, follow=True)
            assert not ScanSession.objects.exists()
            task.assert_not_called()
            assert b"must be authorized" in resp.content
            DomainAuthorization.objects.create(
                domain=Domain.objects.get(name="example.com"), auth_type="owner",
                authorized_at="2026-01-01", authorized_by="admin")
            client.post("/scan/start/", {"domain": "example.com", "workflow_id": wf.id})
        assert ScanSession.objects.count() == 1
        task.assert_called_once()

    def test_unknown_workflow_rejected(self, client):
        from unittest.mock import patch

        with patch("apps.mvp.views.run_scan_task") as task:
            resp = client.post("/scan/start/", {"domain": "example.com", "workflow_id": "999999"})
        assert resp.status_code == 302
        task.assert_not_called()

    def test_detail_renders_modes(self, client):
        resp = client.get("/domains/example.com/")
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
        resp = client.get(f"/scan/{self.s.uuid}/")
        body = resp.content.decode()
        assert resp.status_code == 200
        assert "High thing" in body and "subfinder" in body
        assert "every 3s" in body

    def test_terminal_detail_has_no_poll_trigger(self, client):
        self.s.status = "completed"
        self.s.save()
        assert "every 3s" not in client.get(f"/scan/{self.s.uuid}/").content.decode()

    def test_progress_partial(self, client):
        resp = client.get(f"/scan/{self.s.uuid}/progress/")
        body = resp.content.decode()
        assert resp.status_code == 200
        assert "nuclei" in body and "Failed:" in body and "1 high" in body

    def test_progress_terminal_refreshes(self, client):
        self.s.status = "completed"
        self.s.save()
        resp = client.get(f"/scan/{self.s.uuid}/progress/")
        assert resp.status_code == 204 and resp["HX-Refresh"] == "true"

    def test_cancel_flips_status(self, client):
        from unittest.mock import patch

        with patch("apps.core.engine.scheduler.scheduler._cancel_workflows_for_sessions") as c:
            resp = client.post(f"/scan/{self.s.uuid}/cancel/")
        assert resp.status_code == 302
        self.s.refresh_from_db()
        assert self.s.status == "cancelled" and self.s.end_time
        c.assert_called_once_with([self.s.id])

    def test_sev_filter(self, client):
        body = client.get(f"/scan/{self.s.uuid}/?sev=high").content.decode()
        assert "High thing" in body and "Low thing" not in body


@pytest.mark.django_db
class TestScans:
    @pytest.fixture(autouse=True)
    def _seed(self, client):
        from apps.core.engine.scans.models import ScanSession

        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        self.a = ScanSession.objects.create(domain="example.com", status="completed")
        self.b = ScanSession.objects.create(domain="example.com", status="failed")
        self.c = ScanSession.objects.create(domain="other.org", status="completed")

    def test_lists_all(self, client):
        resp = client.get("/scans/")
        body = resp.content.decode()
        assert resp.status_code == 200
        for s in (self.a, self.b, self.c):
            assert str(s.uuid) in body

    def test_status_filter(self, client):
        body = client.get("/scans/?status=completed").content.decode()
        assert str(self.a.uuid) in body and str(self.c.uuid) in body
        assert str(self.b.uuid) not in body

    def test_domain_filter(self, client):
        body = client.get("/scans/?domain=other.org").content.decode()
        assert str(self.c.uuid) in body
        assert str(self.a.uuid) not in body and str(self.b.uuid) not in body


@pytest.mark.django_db
class TestChangePassword:
    def _flagged(self, client, flag=True):
        from apps.core.console.dashboard.models import UserProfile

        u = User.objects.create_user("admin", password="pw12345!")
        UserProfile.objects.update_or_create(user=u, defaults={"must_change_password": flag})
        client.login(username="admin", password="pw12345!")
        return u

    def test_flagged_user_redirected(self, client):
        self._flagged(client)
        resp = client.get("/")
        assert resp.status_code == 302 and resp["Location"] == "/change-password/"

    def test_page_reachable_while_flagged(self, client):
        self._flagged(client)
        assert client.get("/change-password/").status_code == 200

    def test_valid_change_clears_flag(self, client):
        u = self._flagged(client)
        resp = client.post(
            "/change-password/",
            {"old_password": "pw12345!", "new_password1": "Xk9#mQ2vLp77", "new_password2": "Xk9#mQ2vLp77"},
        )
        assert resp.status_code == 302
        u.profile.refresh_from_db()
        assert u.profile.must_change_password is False
        assert client.get("/").status_code == 200

    def test_overlong_password_rejected(self, client):
        u = self._flagged(client)
        long_pw = "aB3$" * 40
        resp = client.post(
            "/change-password/",
            {"old_password": "pw12345!", "new_password1": long_pw, "new_password2": long_pw},
        )
        assert resp.status_code == 200
        u.profile.refresh_from_db()
        assert u.profile.must_change_password is True

    def test_unflagged_user_passes(self, client):
        self._flagged(client, flag=False)
        assert client.get("/").status_code == 200


@pytest.mark.django_db
class TestFindings:
    @pytest.fixture(autouse=True)
    def _seed(self, client):
        from apps.core.data.findings.models import Finding
        from apps.core.engine.scans.models import ScanSession

        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        s = ScanSession.objects.create(domain="example.com", status="completed")
        Finding.objects.create(session=s, source="nuclei", severity="low", title="Low one", target="a")
        Finding.objects.create(session=s, source="nuclei", severity="high", title="High one", target="b")
        Finding.objects.create(session=s, source="web_checker", severity="critical", title="Crit one",
                               target="c", status="resolved")
        self.session = s

    def test_requires_login(self, client):
        client.logout()
        resp = client.get("/findings/")
        assert resp.status_code == 302 and resp["Location"].startswith("/login/")

    def test_lists_all_sorted_by_severity(self, client):
        resp = client.get("/findings/")
        assert resp.status_code == 200
        body = resp.content.decode()
        assert "Low one" in body and "High one" in body and "Crit one" in body
        assert body.index("Crit one") < body.index("High one") < body.index("Low one")
        assert str(self.session.uuid) in body

    def test_filter_severity(self, client):
        body = client.get("/findings/?severity=high").content.decode()
        assert "High one" in body and "Low one" not in body and "Crit one" not in body

    def test_filter_status(self, client):
        body = client.get("/findings/?status=resolved").content.decode()
        assert "Crit one" in body and "High one" not in body

    def test_filter_source(self, client):
        body = client.get("/findings/?source=web_checker").content.decode()
        assert "Crit one" in body and "High one" not in body

    def test_filter_domain_and_invalid_values_ignored(self, client):
        assert "High one" in client.get("/findings/?domain=EXAMPLE").content.decode()
        assert "No findings match" in client.get("/findings/?domain=nope.org").content.decode()
        assert "High one" in client.get("/findings/?severity=bogus&status=bogus").content.decode()


@pytest.mark.django_db
class TestIssues:
    @pytest.fixture(autouse=True)
    def _setup(self, client):
        from django.utils import timezone

        from apps.core.data.domains.models import Domain
        from apps.core.data.issues.models import Issue

        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        d = Domain.objects.create(name="example.com")
        now = timezone.now()

        def mk(key, title, sev, status="open"):
            return Issue.objects.create(
                domain=d, key=key, check_id=key, source="nuclei", title=title,
                target="example.com", severity=sev, status=status,
                first_seen=now, last_seen=now,
            )

        self.hi = mk("a", "Alpha high issue", "high")
        self.lo = mk("b", "Beta low issue", "low", status="resolved")

    def test_list_and_filters(self, client):
        body = client.get("/issues/").content.decode()
        assert "Alpha high issue" in body and "Beta low issue" in body
        body = client.get("/issues/?status=open").content.decode()
        assert "Alpha high issue" in body and "Beta low issue" not in body
        body = client.get("/issues/?severity=low").content.decode()
        assert "Beta low issue" in body and "Alpha high issue" not in body

    def test_requires_login(self, client):
        client.logout()
        assert client.get("/issues/").status_code == 302

    def test_update_persists_and_resolved_at(self, client):
        resp = client.post(f"/issues/{self.hi.id}/update/", {
            "status": "resolved", "assigned_to": " bob ", "resolution_note": "patched",
        })
        assert resp.status_code == 302
        self.hi.refresh_from_db()
        assert (self.hi.status, self.hi.assigned_to, self.hi.resolution_note) == ("resolved", "bob", "patched")
        assert self.hi.resolved_at is not None
        client.post(f"/issues/{self.hi.id}/update/", {"status": "open"})
        self.hi.refresh_from_db()
        assert self.hi.status == "open" and self.hi.resolved_at is None

    def test_invalid_status_rejected(self, client):
        client.post(f"/issues/{self.hi.id}/update/", {"status": "bogus", "assigned_to": "x"})
        self.hi.refresh_from_db()
        assert self.hi.status == "open" and self.hi.assigned_to == ""
