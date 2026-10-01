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
        import apps.core.engine.workflows.registry as reg
        fake = {
            "mystery": {"active": True, "quick_recon": True},
            "domain_security": {"active": False, "quick_recon": True},
        }
        monkeypatch.setattr(reg, "get_registry", lambda: fake)
        assert reg.light_passive_tools() == {"domain_security"}
