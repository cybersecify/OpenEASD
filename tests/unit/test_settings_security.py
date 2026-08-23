"""Unit tests for the SECRET_KEY production guard in openeasd/settings.py."""

from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured

from openeasd.settings import (
    _validate_secret_key, _security_settings, _resolve_profile, _PROFILE_TUNING,
)


class TestResourceProfile:
    def test_profile_tuning_values(self):
        assert _PROFILE_TUNING["low"]["nuclei_c"] == 10
        assert _PROFILE_TUNING["balanced"]["nuclei_c"] == 25
        assert _PROFILE_TUNING["high"]["nuclei_c"] == 40

    def test_high_rate_stays_polite(self):
        # Per-target request rate must scale politely, NOT with local specs —
        # cranking it just trips WAFs. Keep 'high' within a sane ceiling.
        assert _PROFILE_TUNING["high"]["nuclei_rate"] <= 150

    def test_auto_detects_low_on_small_ram(self):
        with patch("openeasd.settings._detect_ram_gb", return_value=1.0):
            assert _resolve_profile() == "low"

    def test_auto_detects_high_on_big_ram(self):
        with patch("openeasd.settings._detect_ram_gb", return_value=16.0):
            assert _resolve_profile() == "high"

    def test_auto_detects_balanced_on_mid_ram(self):
        with patch("openeasd.settings._detect_ram_gb", return_value=4.0):
            assert _resolve_profile() == "balanced"

    def test_unknown_ram_defaults_balanced(self):
        with patch("openeasd.settings._detect_ram_gb", return_value=None):
            assert _resolve_profile() == "balanced"


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


class TestSecretKeyGuardWiring:
    """The helper is unit-tested above, but nothing proved the guard is actually
    WIRED into settings import. Deleting the call would boot production with the
    insecure default key (which also signs JWTs). Prove boot aborts, in a real
    subprocess (the in-process guard is skipped under pytest by design)."""

    def test_settings_import_aborts_on_insecure_key_in_production(self):
        import os
        import subprocess
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[2]
        env = {
            **os.environ,
            "SECRET_KEY": "django-insecure-change-me-in-production",
            "DEBUG": "False",
        }
        # Ensure nothing pre-marks pytest in the child so the guard runs.
        env.pop("PYTEST_CURRENT_TEST", None)
        result = subprocess.run(
            [sys.executable, "-c", "import openeasd.settings"],
            cwd=str(repo_root), env=env, capture_output=True, text=True,
        )
        assert result.returncode != 0, "settings booted with an insecure key + DEBUG=False"
        assert "ImproperlyConfigured" in result.stderr or "SECRET_KEY" in result.stderr

    def test_settings_import_succeeds_with_strong_key(self):
        import os
        import subprocess
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[2]
        env = {
            **os.environ,
            "SECRET_KEY": "x" * 50,  # strong enough to pass the guard
            "DEBUG": "False",
        }
        env.pop("PYTEST_CURRENT_TEST", None)
        result = subprocess.run(
            [sys.executable, "-c", "import openeasd.settings"],
            cwd=str(repo_root), env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
