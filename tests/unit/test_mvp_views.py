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
