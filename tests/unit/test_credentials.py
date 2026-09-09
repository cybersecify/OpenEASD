"""Tests for the credentials app (C1) — model, resolver, write-only API."""

import pytest
from django.contrib.auth.models import User
from ninja_jwt.tokens import AccessToken

pytestmark = pytest.mark.django_db


@pytest.fixture
def auth_client(client):
    user = User.objects.create_user(username="credtest", password="pass123")
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {AccessToken.for_user(user)}"
    return client


# --- model ---------------------------------------------------------------

class TestModel:
    def test_singleton(self):
        from apps.core.console.credentials.models import ToolCredentials
        a = ToolCredentials.get()
        b = ToolCredentials.get()
        assert a.pk == 1 and b.pk == 1
        assert ToolCredentials.objects.count() == 1

    def test_ciphertext_at_rest_plaintext_via_orm(self):
        """DB column holds ciphertext; ORM attribute returns plaintext."""
        from django.db import connection
        from apps.core.console.credentials.models import ToolCredentials
        cfg = ToolCredentials.get()
        cfg.shodan_api_key = "SECRET-shodan-123"
        cfg.save()
        # ORM round-trip → plaintext
        assert ToolCredentials.get().shodan_api_key == "SECRET-shodan-123"
        # raw column → not the plaintext (Fernet ciphertext)
        with connection.cursor() as cur:
            cur.execute("SELECT shodan_api_key FROM credentials_toolcredentials WHERE id=1")
            raw = cur.fetchone()[0]
        assert raw and raw != "SECRET-shodan-123"


# --- resolver (DB-wins-over-env) ----------------------------------------

class TestResolver:
    def test_db_value_wins_over_env(self, settings):
        from apps.core.console.credentials.models import ToolCredentials
        from apps.core.console.credentials.resolver import get_credential
        settings.SHODAN_API_KEY = "env-key"
        cfg = ToolCredentials.get()
        cfg.shodan_api_key = "db-key"
        cfg.save()
        assert get_credential("SHODAN_API_KEY") == "db-key"

    def test_env_fallback_when_db_empty(self, settings):
        from apps.core.console.credentials.resolver import get_credential
        settings.HIBP_API_KEY = "env-hibp"
        assert get_credential("HIBP_API_KEY") == "env-hibp"

    def test_empty_when_neither_set(self, settings):
        from apps.core.console.credentials.resolver import get_credential
        settings.GITHUB_TOKEN = ""
        assert get_credential("GITHUB_TOKEN") == ""

    def test_source_reporting(self, settings):
        from apps.core.console.credentials.models import ToolCredentials
        from apps.core.console.credentials.resolver import credential_source
        settings.SHODAN_API_KEY = ""
        settings.HIBP_API_KEY = "env-hibp"
        cfg = ToolCredentials.get()
        cfg.github_token = "db-gh"
        cfg.save()
        assert credential_source("GITHUB_TOKEN") == "db"
        assert credential_source("HIBP_API_KEY") == "env"
        assert credential_source("SHODAN_API_KEY") == "none"

    def test_never_raises_on_db_error(self, settings, monkeypatch):
        from apps.core.console.credentials import resolver
        settings.SHODAN_API_KEY = "env-fallback"

        def boom():
            raise RuntimeError("db down")

        monkeypatch.setattr(
            "apps.core.console.credentials.models.ToolCredentials.get", staticmethod(boom)
        )
        # falls back to env, no exception
        assert resolver.get_credential("SHODAN_API_KEY") == "env-fallback"


# --- API (write-only) ----------------------------------------------------

class TestApi:
    def test_requires_auth(self, client):
        assert client.get("/api/credentials/").status_code == 401

    def test_get_presence_only_never_values(self, auth_client):
        from apps.core.console.credentials.models import ToolCredentials
        cfg = ToolCredentials.get()
        cfg.shodan_api_key = "super-secret"
        cfg.save()
        body = auth_client.get("/api/credentials/").json()
        assert body["configured"]["shodan_api_key"] is True
        assert body["configured"]["hibp_api_key"] is False
        # the actual value must never appear anywhere in the response
        assert "super-secret" not in str(body)

    def test_post_sets_key(self, auth_client):
        from apps.core.console.credentials.models import ToolCredentials
        resp = auth_client.post(
            "/api/credentials/",
            data={"shodan_api_key": "new-key"},
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.json()["configured"]["shodan_api_key"] is True
        assert ToolCredentials.get().shodan_api_key == "new-key"

    def test_post_none_leaves_unchanged(self, auth_client):
        from apps.core.console.credentials.models import ToolCredentials
        cfg = ToolCredentials.get()
        cfg.shodan_api_key = "keep-me"
        cfg.save()
        # omit shodan → None → unchanged; set hibp
        auth_client.post(
            "/api/credentials/",
            data={"hibp_api_key": "hibp-new"},
            content_type="application/json",
        )
        cfg = ToolCredentials.get()
        assert cfg.shodan_api_key == "keep-me"
        assert cfg.hibp_api_key == "hibp-new"

    def test_post_empty_string_clears(self, auth_client):
        from apps.core.console.credentials.models import ToolCredentials
        cfg = ToolCredentials.get()
        cfg.shodan_api_key = "to-clear"
        cfg.save()
        auth_client.post(
            "/api/credentials/",
            data={"shodan_api_key": ""},
            content_type="application/json",
        )
        assert ToolCredentials.get().shodan_api_key == ""
