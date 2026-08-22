"""The default workflow is 'Full Scan' with the complete tool set (migration 0021)."""

import pytest


_EXPECTED_FULL_SCAN = {
    "domain_security", "subfinder", "amass", "alterx", "dnsx",
    "takeover_check", "cloud_assets", "naabu", "nmap", "tls_checker",
    "ssh_checker", "nuclei_network", "httpx", "historical_urls", "katana",
    "nuclei", "web_checker", "cve_intel",
    # added in 0023 so registry (21) == Full Scan == report tool count
    "asn_discovery", "js_secrets",
}


@pytest.mark.django_db
def test_default_is_full_scan():
    from apps.core.workflows.models import Workflow
    default = Workflow.objects.get(is_default=True)
    assert default.name == "Full Scan"


@pytest.mark.django_db
def test_exactly_one_default():
    from apps.core.workflows.models import Workflow
    assert Workflow.objects.filter(is_default=True).count() == 1


@pytest.mark.django_db
def test_full_scan_has_complete_tool_set():
    from apps.core.workflows.models import Workflow
    wf = Workflow.objects.get(name="Full Scan")
    tools = set(wf.steps.values_list("tool", flat=True))
    assert _EXPECTED_FULL_SCAN <= tools, f"missing: {_EXPECTED_FULL_SCAN - tools}"


@pytest.mark.django_db
def test_forward_is_idempotent_and_fills_gaps():
    """Re-running the promotion on a partial Full Scan adds only missing tools."""
    import importlib
    from django.apps import apps as django_apps
    from apps.core.workflows.models import Workflow, WorkflowStep

    _0021 = importlib.import_module(
        "apps.core.workflows.migrations.0021_set_full_scan_default_and_complete"
    )

    wf = Workflow.objects.get(name="Full Scan")
    # Simulate an older/partial Full Scan: keep only three tools.
    WorkflowStep.objects.filter(workflow=wf).exclude(
        tool__in=["domain_security", "subfinder", "httpx"]
    ).delete()
    assert wf.steps.count() == 3

    _0021.set_full_scan_default(django_apps, None)

    tools = set(wf.steps.values_list("tool", flat=True))
    # 0021 restores its own canonical 18; asn_discovery/js_secrets are added by
    # the separate migration 0023, so exclude them from this migration's check.
    assert (_EXPECTED_FULL_SCAN - {"asn_discovery", "js_secrets"}) <= tools
    # no duplicates introduced
    assert wf.steps.count() == len(set(wf.steps.values_list("tool", flat=True)))
