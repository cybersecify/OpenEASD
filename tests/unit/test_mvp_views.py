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
