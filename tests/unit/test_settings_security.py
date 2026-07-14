"""Unit tests for the SECRET_KEY production guard in openeasd/settings.py."""

import pytest
from django.core.exceptions import ImproperlyConfigured

from openeasd.settings import _validate_secret_key


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
