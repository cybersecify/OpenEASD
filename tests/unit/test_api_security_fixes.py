"""Tests for the API security-review fixes (H1, M1, M2, M4).

- H1: /notifications/test/ must not leak the webhook URL (secret) in its error.
- M1: report downloads must honour the must_change_password gate.
- M2: change-password must blacklist the user's outstanding refresh tokens.
- M4: change-password must reject an over-long new password.
"""

from unittest.mock import patch

import pytest
import requests
from django.contrib.auth.models import User
from django.test import Client
from ninja_jwt.tokens import AccessToken, RefreshToken

pytestmark = pytest.mark.django_db


def _bearer(user):
    return {"HTTP_AUTHORIZATION": f"Bearer {AccessToken.for_user(user)}"}


@pytest.fixture
def user(db):
    return User.objects.create_user(username="admin", password="longpass1")


# --- H1: webhook secret not leaked in test-alert error -----------------------

class TestWebhookSecretNotLeaked:
    def test_failed_slack_test_does_not_leak_url(self, user):
        from apps.core.console.notifications.models import NotificationConfig
        secret_url = "https://hooks.slack.com/services/T000/B000/SUPERSECRETTOKEN"
        cfg = NotificationConfig.objects.get_or_create(pk=1)[0]
        cfg.slack_webhook_url = secret_url
        cfg.save()

        # requests raises with the full URL embedded — the classic leak vector.
        boom = requests.exceptions.HTTPError(
            f"404 Client Error: Not Found for url: {secret_url}"
        )
        # api.py does `import requests as req_lib` inside the view, so patch the
        # real requests.post.
        with patch("requests.post", side_effect=boom):
            resp = Client().post(
                "/api/notifications/test/",
                data='{"channel":"slack"}',
                content_type="application/json",
                **_bearer(user),
            )
        assert resp.status_code == 502
        body = resp.content.decode()
        assert "SUPERSECRETTOKEN" not in body
        assert "hooks.slack.com/services" not in body
        assert "Webhook delivery failed" in body


# --- M1: report download honours must_change_password ------------------------

class TestReportPasswordGate:
    def _session(self):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(domain="ex.com", status="completed")

    def _flag(self, user):
        from apps.core.console.dashboard.models import UserProfile
        p, _ = UserProfile.objects.get_or_create(user=user)
        p.must_change_password = True
        p.save()

    def test_flagged_user_bearer_is_redirected_not_served(self, user):
        s = self._session()
        self._flag(user)
        resp = Client().get(f"/reports/{s.uuid}/csv/", **_bearer(user))
        assert resp.status_code in (301, 302)
        assert "/change-password" in resp["Location"]

    def test_unflagged_user_bearer_is_served(self, user):
        s = self._session()
        resp = Client().get(f"/reports/{s.uuid}/csv/", **_bearer(user))
        assert resp.status_code == 200


# --- M2 + M4: change-password token revocation + max length ------------------

class TestChangePasswordHardening:
    def test_revokes_outstanding_refresh_tokens(self, user):
        from ninja_jwt.token_blacklist.models import BlacklistedToken
        # Issuing a refresh token records an OutstandingToken row.
        RefreshToken.for_user(user)
        assert BlacklistedToken.objects.count() == 0
        resp = Client().post(
            "/api/user/change-password/",
            data='{"current_password":"longpass1","new_password":"newlongpass9"}',
            content_type="application/json",
            **_bearer(user),
        )
        assert resp.status_code == 200
        # The user's outstanding refresh token is now blacklisted.
        assert BlacklistedToken.objects.count() >= 1

    def test_rejects_overlong_new_password(self, user):
        resp = Client().post(
            "/api/user/change-password/",
            data='{"current_password":"longpass1","new_password":"%s"}' % ("x" * 200),
            content_type="application/json",
            **_bearer(user),
        )
        assert resp.status_code == 400
        assert "128" in resp.json()["error"]["message"]
