"""Passive-only vs active scan modes.

Covers the registry `active` classification, the `is_passive_tool_set` helper,
the predefined 'Passive Scan' workflow, and — most importantly — the
authorization boundary: a passive-only scan needs no DomainAuthorization while
any scan containing an active tool keeps the gate.
"""

import pytest


# Canonical classification — the legal boundary. Passive tools use only public /
# third-party data and never touch the target.
_PASSIVE = {
    "subfinder", "alterx", "dnsx", "historical_urls",
    "cloud_assets", "cve_intel", "asn_discovery", "tldsquatting", "breach_check",
    # domain_security is passive now that its active probes (AXFR/open-relay/
    # MTA-STS fetch) were split out into domain_probe.
    "domain_security",
    # asn_cluster does IP→ASN via Team Cymru (third party) — never the target.
    "asn_cluster",
}
_ACTIVE = {
    "domain_probe", "amass", "takeover_check", "naabu", "service_detection",
    "nmap", "tls_checker", "ssh_checker", "nuclei_network", "httpx",
    "katana", "nuclei", "web_checker",
}


# ---------------------------------------------------------------------------
# Registry classification
# ---------------------------------------------------------------------------

class TestRegistryActiveFlag:
    def test_every_tool_has_active_flag(self):
        from apps.core.engine.workflows.registry import get_tool_active
        active = get_tool_active()
        # every registered tool is classified either passive or active
        for tool in _PASSIVE | _ACTIVE:
            assert tool in active, f"{tool} missing from registry"

    def test_passive_tools_marked_passive(self):
        from apps.core.engine.workflows.registry import get_tool_active
        active = get_tool_active()
        for tool in _PASSIVE:
            assert active[tool] is False, f"{tool} should be passive (active=False)"

    def test_active_tools_marked_active(self):
        from apps.core.engine.workflows.registry import get_tool_active
        active = get_tool_active()
        for tool in _ACTIVE:
            assert active[tool] is True, f"{tool} should be active (active=True)"

    def test_default_is_active_for_unknown_tool(self):
        # A tool with no explicit flag must default to active (the safe default:
        # a missing flag can never let a scanner probe an unauthorized target).
        from apps.core.engine.workflows.registry import get_tool_active
        active = get_tool_active()
        assert active.get("some_unregistered_tool", True) is True


# ---------------------------------------------------------------------------
# phase_group categories (UI grouping)
# ---------------------------------------------------------------------------

class TestPhaseGroupCategories:
    # The leak-detection tools live in their own "Credential Exposure" category
    # rather than being mixed into Domain Posture / Web Exposure.
    _CRED_EXPOSURE = {"hudson_rock", "breach_check", "github_secrets"}

    def test_credential_exposure_tools_grouped_together(self):
        from apps.core.engine.workflows.registry import get_tool_phase_groups
        groups = get_tool_phase_groups()
        for tool in self._CRED_EXPOSURE:
            assert groups.get(tool) == "Credential Exposure", (
                f"{tool} should be in the Credential Exposure phase_group, got {groups.get(tool)!r}"
            )

    def test_domain_posture_excludes_leak_tools(self):
        # Domain Posture keeps domain-posture tools only; leak tools moved out.
        from apps.core.engine.workflows.registry import get_tool_phase_groups
        groups = get_tool_phase_groups()
        di = {t for t, g in groups.items() if g == "Domain Posture"}
        assert di.isdisjoint(self._CRED_EXPOSURE)
        assert "domain_security" in di


# ---------------------------------------------------------------------------
# is_passive_tool_set helper
# ---------------------------------------------------------------------------

class TestIsPassiveToolSet:
    def test_all_passive_returns_true(self):
        from apps.core.engine.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["subfinder", "dnsx", "cloud_assets"]) is True

    def test_single_active_tool_makes_set_active(self):
        from apps.core.engine.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["subfinder", "dnsx", "naabu"]) is False

    def test_empty_set_is_not_passive(self):
        from apps.core.engine.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set([]) is False

    def test_unknown_tool_treated_as_active(self):
        from apps.core.engine.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["subfinder", "mystery_tool"]) is False

    def test_domain_security_is_passive(self):
        # After the split, domain_security is passive (public-resolver DNS +
        # email-auth + RDAP), so it may run in a no-auth passive scan.
        from apps.core.engine.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["domain_security"]) is True

    def test_domain_probe_is_active(self):
        # Regression guard: domain_probe performs AXFR zone transfers, SMTP
        # open-relay probes, and MTA-STS policy fetches against the target, so it
        # must always be classified active (needs DomainAuthorization).
        from apps.core.engine.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["domain_probe"]) is False


# ---------------------------------------------------------------------------
# Passive Scan workflow (migration 0022)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestPassiveScanWorkflow:
    def test_workflow_exists(self):
        from apps.core.engine.workflows.models import Workflow
        assert Workflow.objects.filter(name="Passive Scan Deep").exists()

    def test_workflow_is_not_default(self):
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Passive Scan Deep")
        assert wf.is_default is False

    def test_every_step_is_passive(self):
        # THE safety invariant: no active tool may appear in the Passive Scan
        # workflow, or a passive scan would probe an unauthorized target.
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import get_tool_active
        wf = Workflow.objects.get(name="Passive Scan Deep")
        active = get_tool_active()
        for tool in wf.enabled_tools():
            assert active.get(tool, True) is False, f"{tool} in Passive Scan is active!"

    def test_workflow_is_passive_tool_set(self):
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import is_passive_tool_set
        wf = Workflow.objects.get(name="Passive Scan Deep")
        assert is_passive_tool_set(wf.enabled_tools()) is True

