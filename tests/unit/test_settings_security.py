"""Unit tests for the SECRET_KEY production guard in openeasd/settings/."""

from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured

from openeasd.settings import (
    _validate_secret_key, _validate_db_password, _under_pytest, _security_settings,
    _resolve_profile, _PROFILE_TUNING,
)


class TestResourceProfile:
    def test_profile_tuning_values(self):
        assert _PROFILE_TUNING["low"]["nuclei_c"] == 10
        assert _PROFILE_TUNING["balanced"]["nuclei_c"] == 25
        assert _PROFILE_TUNING["high"]["nuclei_c"] == 40

    def test_nuclei_severity_drops_info_everywhere(self):
        # info (~38% of templates) is dropped in every profile — it's the freeze
        # + timeout driver and is noise for a prioritised attack-surface report.
        for prof in ("low", "balanced", "high"):
            sev = _PROFILE_TUNING[prof]["nuclei_sev"].split(",")
            assert "info" not in sev
            assert "critical" in sev and "high" in sev and "medium" in sev

    def test_all_profiles_keep_low_severity(self):
        # Deliver complete findings: every profile includes `low` (only info,
        # tech-detect noise already covered by httpx, is dropped). Don't limit
        # real output — give tools the time to finish instead.
        for prof in ("low", "balanced", "high"):
            assert "low" in _PROFILE_TUNING[prof]["nuclei_sev"].split(",")

    def test_bulk_size_scales_down_on_low_profile(self):
        # -bulk-size is the real peak-memory lever: smallest on the 1 GB box.
        assert _PROFILE_TUNING["low"]["nuclei_bs"] < _PROFILE_TUNING["balanced"]["nuclei_bs"]
        assert _PROFILE_TUNING["balanced"]["nuclei_bs"] <= _PROFILE_TUNING["high"]["nuclei_bs"]
        assert _PROFILE_TUNING["low"]["nuclei_bs"] <= 5

    def test_high_rate_stays_polite(self):
        # Per-target request rate must scale politely, NOT with local specs —
        # cranking it just trips WAFs. Keep 'high' within a sane ceiling.
        assert _PROFILE_TUNING["high"]["nuclei_rate"] <= 150

    def test_auto_detects_low_on_small_ram(self):
        with patch("openeasd.settings.base._detect_ram_gb", return_value=1.0):
            assert _resolve_profile() == "low"

    def test_auto_detects_high_on_big_ram(self):
        with patch("openeasd.settings.base._detect_ram_gb", return_value=16.0):
            assert _resolve_profile() == "high"

    def test_auto_detects_balanced_on_mid_ram(self):
        with patch("openeasd.settings.base._detect_ram_gb", return_value=4.0):
            assert _resolve_profile() == "balanced"

    def test_unknown_ram_defaults_balanced(self):
        with patch("openeasd.settings.base._detect_ram_gb", return_value=None):
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
            # A strong DB_PASSWORD too — the production boot now also refuses the
            # default DB password (see TestDbPasswordGuard), so a valid prod boot
            # must satisfy both guards.
            "DB_PASSWORD": "a-strong-db-password",
            "DATABASE_URL": "",  # force the DB_* path, ignoring any repo .env
            "DEBUG": "False",
        }
        env.pop("PYTEST_CURRENT_TEST", None)
        result = subprocess.run(
            [sys.executable, "-c", "import openeasd.settings"],
            cwd=str(repo_root), env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr


class TestDbPasswordGuard:
    def test_raises_on_default_password_in_production(self):
        with pytest.raises(ImproperlyConfigured):
            _validate_db_password(using_database_url=False, db_password="openeasd", debug=False)

    def test_allows_default_password_when_debug(self):
        # Local dev is permitted to keep the placeholder password.
        _validate_db_password(using_database_url=False, db_password="openeasd", debug=True)

    def test_allows_strong_password_in_production(self):
        _validate_db_password(using_database_url=False, db_password="s3cure-p@ss", debug=False)

    def test_database_url_path_is_exempt(self):
        # DATABASE_URL carries its own credentials — the DB_* default never applies,
        # so the guard must not fire even if db_password is left at the default.
        _validate_db_password(using_database_url=True, db_password="openeasd", debug=False)


class TestDbPasswordGuardWiring:
    """Prove the DB-password guard is actually WIRED into settings import — a
    real subprocess, since the in-process call is skipped under pytest. A strong
    SECRET_KEY is set so boot reaches the DB guard rather than aborting earlier."""

    def test_settings_import_aborts_on_default_db_password_in_production(self):
        import os
        import subprocess
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[2]
        env = {
            **os.environ,
            "SECRET_KEY": "x" * 50,        # pass the SECRET_KEY guard first
            "DB_PASSWORD": "openeasd",     # the insecure default
            "DATABASE_URL": "",            # force the DB_* path, ignoring any repo .env
            "DEBUG": "False",
        }
        env.pop("PYTEST_CURRENT_TEST", None)
        result = subprocess.run(
            [sys.executable, "-c", "import openeasd.settings"],
            cwd=str(repo_root), env=env, capture_output=True, text=True,
        )
        assert result.returncode != 0, "settings booted with the default DB password + DEBUG=False"
        assert "ImproperlyConfigured" in result.stderr or "DB_PASSWORD" in result.stderr


class TestPytestRunnerDetection:
    """F-sec2: the production guards skip only under the pytest *runner*
    (argv[0]), not merely because pytest is importable."""

    def test_true_under_the_pytest_runner(self):
        # This suite runs under pytest, so argv[0] is the pytest console script.
        assert _under_pytest() is True

    def test_false_for_non_pytest_entrypoints(self):
        import sys
        for argv0 in ("/usr/local/bin/gunicorn", "manage.py", "-c", ""):
            with patch.object(sys, "argv", [argv0]):
                assert _under_pytest() is False

    def test_guard_fires_even_when_pytest_is_importable(self):
        # The core F-sec2 regression: a process that merely imports pytest (a
        # transitive dep, a debug shell) must NOT get the guard disabled — only
        # the runner (argv[0]) skips it. Import pytest THEN settings with an
        # insecure key + DEBUG=False in a subprocess; it must still abort.
        import os
        import subprocess
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[2]
        env = {
            **os.environ,
            "SECRET_KEY": "django-insecure-change-me-in-production",
            "DB_PASSWORD": "a-strong-db-password",
            "DATABASE_URL": "",
            "DEBUG": "False",
        }
        env.pop("PYTEST_CURRENT_TEST", None)
        result = subprocess.run(
            [sys.executable, "-c", "import pytest; import openeasd.settings"],
            cwd=str(repo_root), env=env, capture_output=True, text=True,
        )
        assert result.returncode != 0, "guard was bypassed merely because pytest was importable"
        assert "ImproperlyConfigured" in result.stderr or "SECRET_KEY" in result.stderr
