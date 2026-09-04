"""Unit tests for apps/core/ai/api.py — config/consent, connection test,
audit log endpoints."""

import json

import pytest
from unittest.mock import patch

from apps.core.ai.models import AIInvocation, AISettings


def _post(client, path, body):
    return client.post(path, data=json.dumps(body), content_type="application/json")


@pytest.fixture
def configured(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct"
    settings.CLOUDFLARE_API_TOKEN = "tok"
    return settings


@pytest.fixture
def unconfigured(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = ""
    settings.CLOUDFLARE_API_TOKEN = ""
    return settings


@pytest.mark.django_db
class TestConfigEndpoint:
    def test_requires_auth(self, client):
        assert client.get("/api/ai/config/").status_code == 401

    def test_get_shape_never_leaks_values(self, auth_client, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = "SECRET-ACCT-8fd2"
        settings.CLOUDFLARE_API_TOKEN = "SECRET-TOKEN-9ab1"
        resp = auth_client.get("/api/ai/config/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is True
        assert data["account_id_set"] is True
        assert data["api_token_set"] is True
        assert data["enabled"] is False
        assert data["consent_current"] is False
        # Presence booleans only — the values must never appear anywhere.
        body = resp.content.decode()
        assert "SECRET-ACCT-8fd2" not in body
        assert "SECRET-TOKEN-9ab1" not in body

    def test_enable_without_env_400(self, auth_client, unconfigured):
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True, "consent_accepted": True})
        assert resp.status_code == 400
        assert AISettings.get().enabled is False

    def test_enable_without_consent_400(self, auth_client, configured):
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True})
        assert resp.status_code == 400
        assert "CONSENT_REQUIRED" in resp.content.decode()
        assert AISettings.get().enabled is False

    def test_enable_with_consent_stamps_fields(self, auth_client, configured):
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True, "consent_accepted": True})
        assert resp.status_code == 200
        cfg = AISettings.get()
        assert cfg.enabled is True
        assert cfg.consent_current is True
        assert cfg.consent_by == "testuser"
        assert resp.json()["consent_given"] is True

    def test_enable_with_existing_consent_no_restamp_needed(self, auth_client, configured):
        cfg = AISettings.get()
        cfg.record_consent("earlier")
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True})
        assert resp.status_code == 200
        assert AISettings.get().enabled is True
        assert AISettings.get().consent_by == "earlier"  # untouched

    def test_disable_always_succeeds_and_keeps_consent(self, auth_client, unconfigured):
        cfg = AISettings.get()
        cfg.record_consent("admin")
        cfg.enabled = True
        cfg.save()
        resp = _post(auth_client, "/api/ai/config/", {"enabled": False})
        assert resp.status_code == 200
        cfg.refresh_from_db()
        assert cfg.enabled is False
        assert cfg.consent_given_at is not None  # revocation != consent erasure

    def test_stale_consent_version_regates(self, auth_client, configured):
        from apps.core.ai.models import CURRENT_CONSENT_VERSION
        cfg = AISettings.get()
        cfg.record_consent("admin")
        cfg.consent_version = CURRENT_CONSENT_VERSION - 1
        cfg.enabled = False
        cfg.save()
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True})
        assert resp.status_code == 400  # stale consent -> modal again


@pytest.mark.django_db
class TestTestEndpoint:
    def test_unconfigured_400(self, auth_client, unconfigured):
        assert _post(auth_client, "/api/ai/test/", {}).status_code == 400

    def test_success(self, auth_client, configured):
        with patch("apps.core.ai.client.chat_json", return_value={"text": "OK"}):
            resp = _post(auth_client, "/api/ai/test/", {})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "latency_ms" in data and "model" in data

    def test_failure_502(self, auth_client, configured):
        with patch("apps.core.ai.client.chat_json", return_value=None):
            resp = _post(auth_client, "/api/ai/test/", {})
        assert resp.status_code == 502

    def test_allowed_before_consent(self, auth_client, configured):
        assert AISettings.get().consent_given_at is None
        with patch("apps.core.ai.client.chat_json", return_value={"text": "OK"}):
            assert _post(auth_client, "/api/ai/test/", {}).status_code == 200


@pytest.mark.django_db
class TestAuditEndpoint:
    def test_requires_auth(self, client):
        assert client.get("/api/ai/audit/").status_code == 401

    def test_pagination_and_shape(self, auth_client, scan_session):
        for i in range(3):
            AIInvocation.objects.create(
                session=scan_session, session_uuid=scan_session.uuid,
                purpose="triage", model="m", status="ok",
                prompt_tokens=10 + i, completion_tokens=5, finding_ids=[1, 2],
            )
        resp = auth_client.get("/api/ai/audit/?page=1&page_size=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert len(data["results"]) == 2
        row = data["results"][0]
        assert row["domain"] == "example.com"
        assert row["finding_count"] == 2
        assert row["tokens_in"] == 12  # newest first
        # Metadata only — no body-like keys.
        assert not {"prompt", "response", "content", "message"} & set(row.keys())
