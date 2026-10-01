"""Active Light — the light active scan mode (discovery backbone + cheap checks).

Drift-locks the predefined 'Active Light' workflow: exact membership, non-default,
authorization preserved (contains active tools), and — the invariant that keeps
'light' light — excludes every heavy engine.
"""

import pytest

ACTIVE_LIGHT = {
    "subfinder", "dnsx", "naabu", "httpx",
    "domain_probe", "web_checker", "tls_checker", "ssh_checker",
}
HEAVY_ENGINES = {
    "nmap", "nuclei", "nuclei_network", "katana", "amass", "cloud_assets",
    "takeover_check", "js_secrets", "historical_urls", "asn_discovery",
    "asn_cluster", "github_recon", "github_secrets", "shodan", "tldsquatting",
    "cve_intel",
}


@pytest.mark.django_db
class TestActiveLightWorkflow:
    def test_exists_and_not_default(self):
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Active Light")
        assert wf.is_default is False

    def test_membership_is_exact(self):
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Active Light")
        assert set(wf.enabled_tools()) == ACTIVE_LIGHT

    def test_requires_authorization_contains_active(self):
        # Active mode: must NOT be an all-passive set (so the auth gate applies).
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import is_passive_tool_set
        wf = Workflow.objects.get(name="Active Light")
        assert is_passive_tool_set(wf.enabled_tools()) is False

    def test_excludes_every_heavy_engine(self):
        # Light stays light — no slow template/enumeration engines.
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Active Light")
        assert set(wf.enabled_tools()).isdisjoint(HEAVY_ENGINES)

    def test_includes_discovery_backbone(self):
        # naabu present → service_detection auto-injects and httpx/tls/ssh get ports.
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Active Light")
        assert "naabu" in wf.enabled_tools()
