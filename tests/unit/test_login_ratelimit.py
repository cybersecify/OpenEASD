"""Tests for login brute-force rate limiting (apps/core/console/api/ratelimit.py)."""

import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import timezone

from apps.core.console.api import ratelimit
from apps.core.console.dashboard.models import LoginThrottle

pytestmark = pytest.mark.django_db


def _login(client, username, password, ip="9.9.9.9"):
    return client.post(
        "/api/token/pair",
        data=json.dumps({"username": username, "password": password}),
        content_type="application/json",
        HTTP_X_FORWARDED_FOR=ip,
    )


class TestHelpers:
    def test_unknown_ip_not_locked(self):
        assert ratelimit.seconds_locked("1.1.1.1") == 0

    def test_locks_after_threshold(self, settings):
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 3
        ratelimit.register_failure("2.2.2.2")
        ratelimit.register_failure("2.2.2.2")
        assert ratelimit.seconds_locked("2.2.2.2") == 0  # below threshold
        ratelimit.register_failure("2.2.2.2")  # 3rd -> lock
        assert ratelimit.seconds_locked("2.2.2.2") > 0

    def test_success_clears_failures(self, settings):
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 2
        ratelimit.register_failure("3.3.3.3")
        ratelimit.register_failure("3.3.3.3")
        assert ratelimit.seconds_locked("3.3.3.3") > 0
        ratelimit.register_success("3.3.3.3")
        assert not LoginThrottle.objects.filter(ip="3.3.3.3").exists()
        assert ratelimit.seconds_locked("3.3.3.3") == 0

    def test_elapsed_window_starts_fresh(self, settings):
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 5
        settings.LOGIN_RATELIMIT_WINDOW_SECONDS = 900
        ratelimit.register_failure("4.4.4.4")
        row = LoginThrottle.objects.get(ip="4.4.4.4")
        row.first_failure_at = timezone.now() - timedelta(seconds=1000)
        row.save()
        ratelimit.register_failure("4.4.4.4")
        row.refresh_from_db()
        assert row.failures == 1  # counter reset for the new window

    def test_client_ip_uses_rightmost_forwarded_for(self):
        # The trusted proxy APPENDS the real client IP, so the rightmost XFF
        # entry is trustworthy; the leftmost ("5.5.5.5") is client-forgeable and
        # must NOT be used (keying on it would let a spoofed header evade the limit).
        req = type("R", (), {"META": {
            "HTTP_X_FORWARDED_FOR": "5.5.5.5, 10.0.0.1", "REMOTE_ADDR": "10.0.0.1"}})()
        assert ratelimit.client_ip(req) == "10.0.0.1"

    def test_spoofed_leftmost_forwarded_for_cannot_evade_when_trusted(self, settings):
        # Even with XFF trusted, a client rotating the LEFTMOST (forged) entry
        # keys on the same rightmost proxy-added IP every time → no evasion.
        settings.LOGIN_RATELIMIT_TRUST_FORWARDED_FOR = True
        ip1 = ratelimit.client_ip(type("R", (), {"META": {
            "HTTP_X_FORWARDED_FOR": "1.1.1.1, 10.0.0.9", "REMOTE_ADDR": "10.0.0.9"}})())
        ip2 = ratelimit.client_ip(type("R", (), {"META": {
            "HTTP_X_FORWARDED_FOR": "2.2.2.2, 10.0.0.9", "REMOTE_ADDR": "10.0.0.9"}})())
        assert ip1 == ip2 == "10.0.0.9"

    def test_client_ip_falls_back_to_remote_addr(self):
        req = type("R", (), {"META": {"REMOTE_ADDR": "6.6.6.6"}})()
        assert ratelimit.client_ip(req) == "6.6.6.6"

    def test_client_ip_ignores_forwarded_for_when_untrusted(self, settings):
        # No trusted proxy -> XFF is attacker-controllable, so ignore it and key
        # on the unspoofable REMOTE_ADDR instead.
        settings.LOGIN_RATELIMIT_TRUST_FORWARDED_FOR = False
        req = type("R", (), {"META": {
            "HTTP_X_FORWARDED_FOR": "1.2.3.4", "REMOTE_ADDR": "10.0.0.1"}})()
        assert ratelimit.client_ip(req) == "10.0.0.1"

    def test_spoofed_forwarded_for_cannot_evade_limit_when_untrusted(self, settings):
        # With XFF untrusted, rotating the header per request no longer resets
        # the counter — all requests key on the same REMOTE_ADDR and lock out.
        settings.LOGIN_RATELIMIT_TRUST_FORWARDED_FOR = False
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 3
        get_user_model().objects.create_user(username="rluser", password="correct-pass")
        c = Client()
        for i in range(3):
            r = c.post(
                "/api/token/pair",
                data=json.dumps({"username": "rluser", "password": "wrong"}),
                content_type="application/json",
                HTTP_X_FORWARDED_FOR=f"9.9.9.{i}",  # rotating spoofed IP
                REMOTE_ADDR="203.0.113.7",
            )
            assert r.status_code == 401
        r = c.post(
            "/api/token/pair",
            data=json.dumps({"username": "rluser", "password": "correct-pass"}),
            content_type="application/json",
            HTTP_X_FORWARDED_FOR="9.9.9.99",
            REMOTE_ADDR="203.0.113.7",
        )
        assert r.status_code == 429  # locked despite the rotating XFF


class TestMiddleware:
    def _user(self):
        return get_user_model().objects.create_user(
            username="rluser", password="correct-pass"
        )

    def test_locks_out_after_threshold(self, settings):
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 3
        self._user()
        c = Client()
        for _ in range(3):
            assert _login(c, "rluser", "wrong").status_code == 401
        # Now locked — even the correct password is refused with 429 + Retry-After.
        resp = _login(c, "rluser", "correct-pass")
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After")

    def test_success_before_threshold_resets(self, settings):
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 5
        self._user()
        c = Client()
        _login(c, "rluser", "wrong")
        _login(c, "rluser", "wrong")
        assert _login(c, "rluser", "correct-pass").status_code == 200
        assert not LoginThrottle.objects.filter(ip="9.9.9.9").exists()

    def test_disabled_never_locks(self, settings):
        settings.LOGIN_RATELIMIT_ENABLED = False
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 2
        self._user()
        c = Client()
        resp = None
        for _ in range(4):
            resp = _login(c, "rluser", "wrong")
        assert resp.status_code == 401  # never 429

    def test_lockout_is_per_ip(self, settings):
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 2
        self._user()
        c = Client()
        _login(c, "rluser", "wrong", ip="7.7.7.7")
        _login(c, "rluser", "wrong", ip="7.7.7.7")
        assert _login(c, "rluser", "correct-pass", ip="7.7.7.7").status_code == 429
        # A different client IP is unaffected.
        assert _login(c, "rluser", "correct-pass", ip="8.8.8.8").status_code == 200

    def test_refresh_endpoint_not_limited(self, settings):
        # Only /token/pair is limited; /token/refresh takes a token, not creds.
        settings.LOGIN_RATELIMIT_MAX_FAILURES = 1
        c = Client()
        for _ in range(3):
            resp = c.post(
                "/api/token/refresh",
                data=json.dumps({"refresh": "not-a-real-token"}),
                content_type="application/json",
                HTTP_X_FORWARDED_FOR="7.7.7.7",
            )
        assert resp.status_code != 429  # never rate-limited
