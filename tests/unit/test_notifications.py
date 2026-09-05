"""Unit tests for apps/core/notifications — model, dispatcher helpers, API endpoints."""

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# NotificationConfig model
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNotificationConfig:
    def test_get_creates_singleton_on_first_call(self, db):
        from apps.core.notifications.models import NotificationConfig
        cfg = NotificationConfig.get()
        assert cfg.pk == 1

    def test_get_returns_same_object_on_repeated_calls(self, db):
        from apps.core.notifications.models import NotificationConfig
        a = NotificationConfig.get()
        b = NotificationConfig.get()
        assert a.pk == b.pk
        from apps.core.notifications.models import NotificationConfig as NC
        assert NC.objects.count() == 1

    def test_defaults(self, db):
        from apps.core.notifications.models import NotificationConfig
        cfg = NotificationConfig.get()
        assert cfg.slack_webhook_url == ""
        assert cfg.teams_webhook_url == ""
        assert cfg.severity_threshold == "high"

    def test_str(self, db):
        from apps.core.notifications.models import NotificationConfig
        cfg = NotificationConfig.get()
        assert "high" in str(cfg)


# ---------------------------------------------------------------------------
# Dispatcher URL helpers — DB-first fallback
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestGetWebhookUrls:
    def test_slack_returns_db_url_when_set(self, db):
        from apps.core.notifications.models import NotificationConfig
        from apps.core.notifications.dispatcher import _get_slack_url
        cfg = NotificationConfig.get()
        cfg.slack_webhook_url = "https://hooks.slack.com/db-url"
        cfg.save()
        assert _get_slack_url() == "https://hooks.slack.com/db-url"

    def test_slack_falls_back_to_env_when_db_empty(self, db):
        from apps.core.notifications.dispatcher import _get_slack_url
        with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
            mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/env-url"
            result = _get_slack_url()
        assert result == "https://hooks.slack.com/env-url"

    def test_slack_db_url_takes_priority_over_env(self, db):
        from apps.core.notifications.models import NotificationConfig
        from apps.core.notifications.dispatcher import _get_slack_url
        cfg = NotificationConfig.get()
        cfg.slack_webhook_url = "https://hooks.slack.com/db-url"
        cfg.save()
        with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
            mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/env-url"
            result = _get_slack_url()
        assert result == "https://hooks.slack.com/db-url"

    def test_teams_returns_db_url_when_set(self, db):
        from apps.core.notifications.models import NotificationConfig
        from apps.core.notifications.dispatcher import _get_teams_url
        cfg = NotificationConfig.get()
        cfg.teams_webhook_url = "https://outlook.office.com/db-url"
        cfg.save()
        assert _get_teams_url() == "https://outlook.office.com/db-url"

    def test_teams_falls_back_to_env_when_db_empty(self, db):
        from apps.core.notifications.dispatcher import _get_teams_url
        with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
            mock_settings.MS_TEAMS_WEBHOOK_URL = "https://outlook.office.com/env-url"
            result = _get_teams_url()
        assert result == "https://outlook.office.com/env-url"

    def test_returns_empty_string_when_neither_set(self, db):
        from apps.core.notifications.dispatcher import _get_slack_url, _get_teams_url
        with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
            mock_settings.SLACK_WEBHOOK_URL = ""
            mock_settings.MS_TEAMS_WEBHOOK_URL = ""
            assert _get_slack_url() == ""
            assert _get_teams_url() == ""


# ---------------------------------------------------------------------------
# Notifications API — config endpoints
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNotificationsConfigAPI:
    def _auth_headers(self, client):
        from django.contrib.auth.models import User
        user, _ = User.objects.get_or_create(username="testuser")
        user.set_password("testpass123")
        user.save()
        resp = client.post(
            "/api/token/pair",
            data={"username": "testuser", "password": "testpass123"},
            content_type="application/json",
        )
        token = resp.json()["access"]
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def test_get_config_returns_defaults(self, client, db):
        headers = self._auth_headers(client)
        resp = client.get("/api/notifications/config/", **headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["slack_configured"] is False
        assert data["teams_configured"] is False
        assert data["severity_threshold"] == "high"

    def test_get_config_requires_auth(self, client, db):
        resp = client.get("/api/notifications/config/")
        assert resp.status_code == 401

    def test_post_config_saves_and_returns(self, client, db):
        headers = self._auth_headers(client)
        payload = {
            "slack_webhook_url": "https://hooks.slack.com/test",
            "teams_webhook_url": "",
            "severity_threshold": "medium",
        }
        resp = client.post(
            "/api/notifications/config/",
            data=payload,
            content_type="application/json",
            **headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["slack_configured"] is True
        assert data["teams_configured"] is False
        assert data["severity_threshold"] == "medium"

    def test_post_config_persists_to_db(self, client, db):
        from apps.core.notifications.models import NotificationConfig
        headers = self._auth_headers(client)
        client.post(
            "/api/notifications/config/",
            data={"slack_webhook_url": "https://hooks.slack.com/test", "teams_webhook_url": "", "severity_threshold": "low"},
            content_type="application/json",
            **headers,
        )
        cfg = NotificationConfig.get()
        assert cfg.slack_webhook_url == "https://hooks.slack.com/test"
        assert cfg.severity_threshold == "low"

    def test_post_config_invalid_threshold_returns_400(self, client, db):
        headers = self._auth_headers(client)
        resp = client.post(
            "/api/notifications/config/",
            data={"slack_webhook_url": "", "teams_webhook_url": "", "severity_threshold": "bogus"},
            content_type="application/json",
            **headers,
        )
        assert resp.status_code == 400

    def test_post_config_requires_auth(self, client, db):
        resp = client.post("/api/notifications/config/", data={}, content_type="application/json")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Notifications API — test endpoint
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNotificationsTestAPI:
    def _auth_headers(self, client):
        from django.contrib.auth.models import User
        user, _ = User.objects.get_or_create(username="testuser2")
        user.set_password("testpass123")
        user.save()
        resp = client.post(
            "/api/token/pair",
            data={"username": "testuser2", "password": "testpass123"},
            content_type="application/json",
        )
        token = resp.json()["access"]
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def test_slack_test_succeeds_when_configured(self, client, db):
        from apps.core.notifications.models import NotificationConfig
        cfg = NotificationConfig.get()
        cfg.slack_webhook_url = "https://hooks.slack.com/test"
        cfg.save()
        headers = self._auth_headers(client)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        with patch("requests.post", return_value=mock_resp):
            resp = client.post(
                "/api/notifications/test/",
                data={"channel": "slack"},
                content_type="application/json",
                **headers,
            )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_slack_test_returns_400_when_not_configured(self, client, db):
        headers = self._auth_headers(client)
        resp = client.post(
            "/api/notifications/test/",
            data={"channel": "slack"},
            content_type="application/json",
            **headers,
        )
        assert resp.status_code == 400

    def test_invalid_channel_returns_400(self, client, db):
        headers = self._auth_headers(client)
        resp = client.post(
            "/api/notifications/test/",
            data={"channel": "discord"},
            content_type="application/json",
            **headers,
        )
        assert resp.status_code == 400

    def test_webhook_failure_returns_502(self, client, db):
        from apps.core.notifications.models import NotificationConfig
        cfg = NotificationConfig.get()
        cfg.teams_webhook_url = "https://outlook.office.com/test"
        cfg.save()
        headers = self._auth_headers(client)
        with patch("requests.post", side_effect=Exception("timeout")):
            resp = client.post(
                "/api/notifications/test/",
                data={"channel": "teams"},
                content_type="application/json",
                **headers,
            )
        assert resp.status_code == 502

    def test_requires_auth(self, client, db):
        resp = client.post("/api/notifications/test/", data={"channel": "slack"}, content_type="application/json")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Notifications API — alert history
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNotificationsAlertsAPI:
    def _auth_headers(self, client):
        from django.contrib.auth.models import User
        user, _ = User.objects.get_or_create(username="testuser3")
        user.set_password("testpass123")
        user.save()
        resp = client.post(
            "/api/token/pair",
            data={"username": "testuser3", "password": "testpass123"},
            content_type="application/json",
        )
        token = resp.json()["access"]
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _make_alert(self, alert_type="slack", status="sent"):
        from apps.core.scans.models import ScanSession
        from apps.core.notifications.models import Alert
        session = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        return Alert.objects.create(
            session=session,
            alert_type=alert_type,
            severity_threshold="high",
            status=status,
            message="Test alert",
        )

    def test_returns_paginated_alerts(self, client, db):
        self._make_alert()
        headers = self._auth_headers(client)
        resp = client.get("/api/notifications/alerts/", **headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert len(data["results"]) == 1
        assert data["results"][0]["alert_type"] == "slack"

    def test_empty_list_when_no_alerts(self, client, db):
        headers = self._auth_headers(client)
        resp = client.get("/api/notifications/alerts/", **headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_response_shape(self, client, db):
        self._make_alert(alert_type="teams", status="failed")
        headers = self._auth_headers(client)
        resp = client.get("/api/notifications/alerts/", **headers)
        result = resp.json()["results"][0]
        assert "domain" in result
        assert "session_uuid" in result
        assert "alert_type" in result
        assert "status" in result
        assert "sent_at" in result

    def test_requires_auth(self, client, db):
        resp = client.get("/api/notifications/alerts/")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# AI summary in alert payloads (apps/core/ai integration)
# ---------------------------------------------------------------------------

def _alert_session():
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")


_GROUPED = {"high": [{"title": "TLS expired", "check_type": "tls_expiry", "target": "example.com"}]}


@pytest.mark.django_db
class TestAlertAiSummary:
    def test_slack_payload_identical_without_summary(self):
        from apps.core.notifications.dispatcher import _build_slack_payload
        sess = _alert_session()
        payload = _build_slack_payload(sess, _GROUPED, "high")
        # header, meta section, divider, one severity section — no AI block.
        assert len(payload["blocks"]) == 4
        assert all("Cloudflare" not in str(b) for b in payload["blocks"])

    def test_slack_payload_gains_one_block_with_summary(self):
        from apps.core.ai.models import AISummary
        from apps.core.notifications.dispatcher import _build_slack_payload
        sess = _alert_session()
        AISummary.objects.create(session=sess, kind="alert", text="One urgent issue.")
        payload = _build_slack_payload(sess, _GROUPED, "high")
        assert len(payload["blocks"]) == 5
        assert payload["blocks"][2]["text"]["text"] == "_One urgent issue._"

    def test_summary_truncated_at_cap(self):
        from apps.core.ai.models import AISummary
        from apps.core.notifications.dispatcher import _get_triage_summary
        sess = _alert_session()
        AISummary.objects.create(session=sess, kind="alert", text="x" * 500)
        out = _get_triage_summary(sess)
        assert len(out) == 300
        assert out.endswith("…")

    def test_teams_payload_gains_summary_fact(self):
        from apps.core.ai.models import AISummary
        from apps.core.notifications.dispatcher import _build_teams_payload
        sess = _alert_session()
        AISummary.objects.create(session=sess, kind="alert", text="One urgent issue.")
        payload = _build_teams_payload(sess, _GROUPED, "high")
        facts = payload["sections"][0]["facts"]
        assert facts[0] == {"name": "Summary", "value": "One urgent issue."}
        assert facts[1]["name"] == "HIGH"

    def test_teams_payload_identical_without_summary(self):
        from apps.core.notifications.dispatcher import _build_teams_payload
        sess = _alert_session()
        payload = _build_teams_payload(sess, _GROUPED, "high")
        assert [f["name"] for f in payload["sections"][0]["facts"]] == ["HIGH"]

    def test_report_kind_not_used_for_alerts(self):
        from apps.core.ai.models import AISummary
        from apps.core.notifications.dispatcher import _get_triage_summary
        sess = _alert_session()
        AISummary.objects.create(session=sess, kind="report", text="report text")
        assert _get_triage_summary(sess) is None

    def test_lookup_failure_sends_without_summary(self):
        from apps.core.notifications.dispatcher import _build_slack_payload
        sess = _alert_session()
        with patch("apps.core.ai.models.AISummary.objects") as broken:
            broken.filter.side_effect = RuntimeError("db broke")
            payload = _build_slack_payload(sess, _GROUPED, "high")
        assert len(payload["blocks"]) == 4  # unchanged, no raise
