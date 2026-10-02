"""Quick Recon — the light passive tier.

Covers the registry `quick_recon` flag + its safe default, the
`light_passive_tools()` helper (passive AND quick_recon), and — in Task 2 —
the predefined 'Quick Recon' workflow and its drift lock against the helper.
"""

import pytest

LIGHT = {"domain_security", "dns_history", "hudson_rock", "breach_check"}


class TestQuickReconFlag:
    def test_four_light_tools_flagged(self):
        from apps.core.engine.workflows.registry import get_tool_quick_recon
        qr = get_tool_quick_recon()
        for tool in LIGHT:
            assert qr.get(tool) is True, f"{tool} should be quick_recon"

    def test_flag_defaults_false_for_unflagged_tool(self):
        # A heavy passive tool and an active tool are NOT quick_recon.
        from apps.core.engine.workflows.registry import get_tool_quick_recon
        qr = get_tool_quick_recon()
        assert qr.get("tldsquatting") is False      # passive but heavy
        assert qr.get("nmap") is False              # active
        assert qr.get("subfinder") is False         # passive but heavy

    def test_every_tool_has_a_quick_recon_flag(self):
        from apps.core.engine.workflows.registry import (
            get_tool_quick_recon,
            get_registry,
        )
        qr = get_tool_quick_recon()
        for name in get_registry():
            assert name in qr
            assert isinstance(qr[name], bool)


class TestLightPassiveHelper:
    def test_light_passive_tools_is_exactly_the_four(self):
        from apps.core.engine.workflows.registry import light_passive_tools
        assert light_passive_tools() == LIGHT

    def test_light_tools_are_all_passive(self):
        from apps.core.engine.workflows.registry import (
            light_passive_tools,
            get_tool_active,
        )
        active = get_tool_active()
        for tool in light_passive_tools():
            assert active[tool] is False

    def test_active_tool_with_stray_flag_is_not_light(self, monkeypatch):
        # Defensive: quick_recon=True on an active tool must be a no-op.
        from apps.core.engine.workflows.registry import light_passive_tools
        fake = {
            "mystery": {"active": True, "quick_recon": True},
            "domain_security": {"active": False, "quick_recon": True},
        }
        # Patch get_registry where light_passive_tools looks it up (its own module).
        monkeypatch.setattr(
            "apps.core.engine.workflows.registry.get_registry", lambda: fake
        )
        assert light_passive_tools() == {"domain_security"}


@pytest.mark.django_db
class TestQuickReconWorkflow:
    def test_workflow_exists_and_is_not_default(self):
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Passive Scan Light")
        assert wf.is_default is False

    def test_workflow_membership_equals_light_passive_set(self):
        # Drift lock: the workflow's tools == light_passive_tools(), both ways.
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import light_passive_tools
        wf = Workflow.objects.get(name="Passive Scan Light")
        assert set(wf.enabled_tools()) == light_passive_tools()

    def test_workflow_is_entirely_passive(self):
        # No-auth property: every tool in Quick Recon must be passive.
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import is_passive_tool_set
        wf = Workflow.objects.get(name="Passive Scan Light")
        assert is_passive_tool_set(wf.enabled_tools()) is True


@pytest.mark.django_db
class TestQuickReconToolsApi:
    def test_tools_endpoint_exposes_quick_recon_flag(self, client):
        from django.contrib.auth.models import User
        from ninja_jwt.tokens import AccessToken

        user = User.objects.create_user(username="qr", password="pw-123456")
        token = str(AccessToken.for_user(user))
        resp = client.get(
            "/api/workflows/tools/",
            HTTP_AUTHORIZATION=f"Bearer {token}"
        )
        assert resp.status_code == 200
        by_key = {t["key"]: t for t in resp.json()["tools"]}
        assert by_key["domain_security"]["quick_recon"] is True
        assert by_key["tldsquatting"]["quick_recon"] is False
        # additive: the existing active flag is untouched
        assert by_key["domain_security"]["active"] is False
