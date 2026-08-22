"""Unit tests for the SECRET_KEY production guard in openeasd/settings.py."""

import pytest
from django.core.exceptions import ImproperlyConfigured

from openeasd.settings import _validate_secret_key, _security_settings


class TestSecurityHardening:
    def test_proxy_ssl_header_always_set(self):
        # Set in both modes so the app works behind a TLS-terminating proxy.
        assert _security_settings(debug=True)["SECURE_PROXY_SSL_HEADER"] == (
            "HTTP_X_FORWARDED_PROTO", "https")
        assert "SECURE_PROXY_SSL_HEADER" in _security_settings(debug=False)

    def test_secure_cookies_default_on_in_production(self):
        s = _security_settings(debug=False)
        assert s["SESSION_COOKIE_SECURE"] is True
        assert s["CSRF_COOKIE_SECURE"] is True
        assert s["SECURE_CONTENT_TYPE_NOSNIFF"] is True

    def test_ssl_redirect_and_hsts_default_off(self):
        # Off by default so they don't break a deploy that has no TLS yet.
        s = _security_settings(debug=False)
        assert s["SECURE_SSL_REDIRECT"] is False
        assert s["SECURE_HSTS_SECONDS"] == 0

    def test_debug_mode_applies_no_cookie_hardening(self):
        s = _security_settings(debug=True)
        assert "SESSION_COOKIE_SECURE" not in s  # local dev over http stays usable


class TestSecretKeyGuard:
    def test_raises_on_default_key_in_production(self):
        with pytest.raises(ImproperlyConfigured):
            _validate_secret_key("django-insecure-change-me-in-production", debug=False)

    def test_raises_on_any_insecure_prefixed_key_in_production(self):
        with pytest.raises(ImproperlyConfigured):
            _validate_secret_key("django-insecure-anything", debug=False)

    def test_allows_default_key_when_debug(self):
        # No raise — local dev is permitted to keep the placeholder key.
        _validate_secret_key("django-insecure-change-me-in-production", debug=True)

    def test_allows_real_key_in_production(self):
        # No raise — a properly-set key passes even with DEBUG off.
        _validate_secret_key("a1b2c3d4e5f6-a-real-strong-secret", debug=False)
