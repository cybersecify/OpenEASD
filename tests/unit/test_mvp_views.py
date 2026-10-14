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
