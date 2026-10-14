"""Tests for the credentials app (C1) — model, resolver, write-only API."""

import pytest

pytestmark = pytest.mark.django_db


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


# --- C3: a DB-stored key actually reaches a tool -------------------------

class TestToolWiring:
    def test_db_key_drives_shodan_paid_tier_without_env(self, settings, monkeypatch):
        """A DB Shodan key (no env key) makes shodan.collect take the keyed path."""
        from unittest.mock import MagicMock
        from apps.shodan import collector
        from apps.core.console.credentials.models import ToolCredentials

        settings.SHODAN_API_KEY = ""  # no env key
        cfg = ToolCredentials.get()
        cfg.shodan_api_key = "db-shodan-key"
        cfg.save()

        # capture the key the paid host API is called with
        seen = {}

        def fake_get_json(url, params=None):
            seen["url"] = url
            seen["key"] = (params or {}).get("key")
            return None  # short-circuit; we only assert the tier/key choice

        monkeypatch.setattr(collector, "_get_json", fake_get_json)
        monkeypatch.setattr(collector, "_session_ips", lambda s: ["1.2.3.4"])
        session = MagicMock(id=1)

        collector.collect(session)
        assert seen.get("key") == "db-shodan-key"  # DB key reached the tool
        assert "/shodan/host/" in seen.get("url", "")  # paid tier, not free InternetDB
