"""Unit tests for apps/core/ai/guard.py — feature gate + the agent's
authorization boundary (safety invariant 2)."""

import pytest

from apps.core.ai.guard import gate_subscan_tools, is_ai_active
from apps.core.ai.models import AISettings


def _authorize(domain_name="example.com"):
    from django.utils import timezone
    from apps.core.domains.models import Domain, DomainAuthorization
    dom, _ = Domain.objects.get_or_create(name=domain_name, defaults={"is_active": True})
    DomainAuthorization.objects.get_or_create(
        domain=dom,
        defaults={"auth_type": "owner", "authorized_by": "tester",
                  "authorized_at": timezone.now()},
    )
    return dom


@pytest.fixture
def configured(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct"
    settings.CLOUDFLARE_API_TOKEN = "tok"
    return settings


@pytest.mark.django_db
class TestIsAiActive:
    def test_env_unset_is_inactive_even_if_enabled(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = ""
        settings.CLOUDFLARE_API_TOKEN = ""
        cfg = AISettings.get()
        cfg.enabled = True
        cfg.record_consent("admin")
        assert is_ai_active() is False

    def test_disabled_is_inactive(self, configured):
        cfg = AISettings.get()
        cfg.enabled = False
        cfg.record_consent("admin")
        assert is_ai_active() is False

    def test_no_consent_is_inactive(self, configured):
        cfg = AISettings.get()
        cfg.enabled = True
        cfg.save()
        assert is_ai_active() is False

    def test_all_conditions_met_is_active(self, configured):
        cfg = AISettings.get()
        cfg.enabled = True
        cfg.save()
        cfg.record_consent("admin")
        assert is_ai_active() is True

    def test_stale_consent_version_is_inactive(self, configured):
        from apps.core.ai.models import CURRENT_CONSENT_VERSION
        cfg = AISettings.get()
        cfg.enabled = True
        cfg.save()
        cfg.record_consent("admin")
        cfg.consent_version = CURRENT_CONSENT_VERSION - 1
        cfg.save()
        assert is_ai_active() is False


@pytest.mark.django_db
class TestGateSubscanTools:
    def test_unknown_tools_dropped(self):
        _authorize()
        allowed, reason = gate_subscan_tools("example.com", ["subfinder", "not_a_tool"])
        assert allowed == ["subfinder"]
        assert reason == ""

    def test_all_unknown_denied(self):
        allowed, reason = gate_subscan_tools("example.com", ["bogus", "fake"])
        assert allowed == []
        assert "no known tools" in reason

    def test_empty_denied(self):
        allowed, reason = gate_subscan_tools("example.com", [])
        assert allowed == []

    def test_passive_set_allowed_without_authorization(self):
        # subfinder is passive — no DomainAuthorization row exists, still allowed.
        allowed, reason = gate_subscan_tools("example.com", ["subfinder"])
        assert allowed == ["subfinder"]
        assert reason == ""

    def test_active_set_denied_without_authorization(self):
        # naabu is active (port scanning) — requires DomainAuthorization.
        allowed, reason = gate_subscan_tools("example.com", ["naabu"])
        assert allowed == []
        assert "DomainAuthorization" in reason

    def test_active_set_allowed_with_authorization(self):
        _authorize()
        allowed, reason = gate_subscan_tools("example.com", ["naabu", "subfinder"])
        assert sorted(allowed) == ["naabu", "subfinder"]
        assert reason == ""

    def test_mixed_passive_plus_active_needs_authorization(self):
        # One active tool makes the whole set active (conservative rule).
        allowed, reason = gate_subscan_tools("example.com", ["subfinder", "httpx"])
        assert allowed == []
        assert "DomainAuthorization" in reason
