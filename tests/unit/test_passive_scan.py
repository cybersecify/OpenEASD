"""Passive-only vs active scan modes.

Covers the registry `active` classification, the `is_passive_tool_set` helper,
the predefined 'Passive Scan' workflow, and — most importantly — the
authorization boundary: a passive-only scan needs no DomainAuthorization while
any scan containing an active tool keeps the gate.
"""

import datetime
import json
from unittest.mock import patch

import pytest


def post_json(client, path, data):
    return client.post(path, data=json.dumps(data), content_type="application/json")


# Canonical classification — the legal boundary. Passive tools use only public /
# third-party data and never touch the target.
_PASSIVE = {
    "subfinder", "alterx", "dnsx", "historical_urls",
    "cloud_assets", "cve_intel", "asn_discovery", "typosquat", "breach_check",
    # domain_security is passive now that its active probes (AXFR/open-relay/
    # MTA-STS fetch) were split out into domain_probe.
    "domain_security",
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
    # The leak-detection tools live in their own "Data Leak" category rather than
    # being mixed into Domain Intelligence / Web Exposure.
    _DATA_LEAK = {"hudson_rock", "breach_check", "github_secrets", "js_secrets"}

    def test_data_leak_tools_grouped_together(self):
        from apps.core.engine.workflows.registry import get_tool_phase_groups
        groups = get_tool_phase_groups()
        for tool in self._DATA_LEAK:
            assert groups.get(tool) == "Data Leak", (
                f"{tool} should be in the Data Leak phase_group, got {groups.get(tool)!r}"
            )

    def test_domain_intelligence_excludes_leak_tools(self):
        # Domain Intelligence keeps domain-posture tools only; leak tools moved out.
        from apps.core.engine.workflows.registry import get_tool_phase_groups
        groups = get_tool_phase_groups()
        di = {t for t, g in groups.items() if g == "Domain Intelligence"}
        assert di.isdisjoint(self._DATA_LEAK)
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
        assert Workflow.objects.filter(name="Passive Scan").exists()

    def test_workflow_is_not_default(self):
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Passive Scan")
        assert wf.is_default is False

    def test_every_step_is_passive(self):
        # THE safety invariant: no active tool may appear in the Passive Scan
        # workflow, or a passive scan would probe an unauthorized target.
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import get_tool_active
        wf = Workflow.objects.get(name="Passive Scan")
        active = get_tool_active()
        for tool in wf.enabled_tools():
            assert active.get(tool, True) is False, f"{tool} in Passive Scan is active!"

    def test_workflow_is_passive_tool_set(self):
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import is_passive_tool_set
        wf = Workflow.objects.get(name="Passive Scan")
        assert is_passive_tool_set(wf.enabled_tools()) is True


# ---------------------------------------------------------------------------
# Authorization gate — the critical boundary
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestPassiveScanAuthorizationGate:
    def _passive_workflow_id(self):
        from apps.core.engine.workflows.models import Workflow
        return Workflow.objects.get(name="Passive Scan").id

    def test_passive_scan_bypasses_authorization(self, auth_client, domain):
        # domain fixture (example.com) has NO DomainAuthorization. A passive-only
        # scan must still be accepted — it never touches the target.
        fake_session = type("S", (), {"uuid": "passive-uuid-1", "id": 1})()
        with patch("apps.core.engine.scans.tasks.run_scan_task"), \
             patch("apps.core.engine.scans.pipeline.create_scan_session", return_value=fake_session):
            resp = post_json(auth_client, "/api/scans/start/", {
                "domain": "example.com",
                "schedule_type": "now",
                "workflow_id": self._passive_workflow_id(),
            })
        assert resp.status_code == 201, resp.content
        assert resp.json()["uuid"] == "passive-uuid-1"

    def test_active_workflow_still_requires_authorization(self, auth_client, domain):
        # An explicit active workflow (Full Scan) on an unauthorized domain → 403.
        from apps.core.engine.workflows.models import Workflow
        full = Workflow.objects.get(name="Full Scan")
        resp = post_json(auth_client, "/api/scans/start/", {
            "domain": "example.com",
            "schedule_type": "now",
            "workflow_id": full.id,
        })
        assert resp.status_code == 403
        assert resp.json()["error"]["message"] == "Domain is not authorized for scanning"

    def test_default_now_scan_still_requires_authorization(self, auth_client, domain):
        # No workflow_id → default Full Scan (active) → gate still applies.
        resp = post_json(auth_client, "/api/scans/start/", {
            "domain": "example.com",
            "schedule_type": "now",
        })
        assert resp.status_code == 403

    def test_passive_scan_also_works_when_authorized(self, auth_client, domain):
        from apps.core.data.domains.models import DomainAuthorization
        DomainAuthorization.objects.create(
            domain=domain, auth_type="owner",
            authorized_at=datetime.date(2026, 1, 15), authorized_by="Alice",
        )
        fake_session = type("S", (), {"uuid": "passive-uuid-2", "id": 2})()
        with patch("apps.core.engine.scans.tasks.run_scan_task"), \
             patch("apps.core.engine.scans.pipeline.create_scan_session", return_value=fake_session):
            resp = post_json(auth_client, "/api/scans/start/", {
                "domain": "example.com",
                "schedule_type": "now",
                "workflow_id": self._passive_workflow_id(),
            })
        assert resp.status_code == 201

    def test_scheduled_passive_workflow_id_ignored_gate_applies(self, auth_client, domain):
        # Scheduled (once/recurring) scans run the default active workflow
        # regardless of any workflow_id, so the gate must still apply.
        resp = post_json(auth_client, "/api/scans/start/", {
            "domain": "example.com",
            "schedule_type": "once",
            "scheduled_at": "2030-01-01T03:00:00",
            "workflow_id": self._passive_workflow_id(),
        })
        assert resp.status_code == 403

    def test_passive_tools_subset_bypasses_authorization(self, auth_client, domain):
        # A category-scoped scan of only passive tools on an unauthorized domain
        # is accepted, and the run is restricted to those tools (subscan_tools).
        captured = {}

        def fake_create(domain, triggered_by="manual", workflow=None, tools=None):
            captured["tools"] = tools
            return type("S", (), {"uuid": "cat-uuid-1", "id": 7})()

        with patch("apps.core.engine.scans.tasks.run_scan_task"), \
             patch("apps.core.engine.scans.pipeline.create_scan_session", side_effect=fake_create):
            resp = post_json(auth_client, "/api/scans/start/", {
                "domain": "example.com",
                "schedule_type": "now",
                "tools": ["cve_intel"],  # passive
            })
        assert resp.status_code == 201, resp.content
        assert captured["tools"] == ["cve_intel"]

    def test_active_tools_subset_requires_authorization(self, auth_client, domain):
        # Including an active tool (e.g. domain_probe — AXFR/open-relay/MTA-STS)
        # keeps the auth gate, even alongside passive tools.
        resp = post_json(auth_client, "/api/scans/start/", {
            "domain": "example.com",
            "schedule_type": "now",
            "tools": ["typosquat", "domain_probe"],
        })
        assert resp.status_code == 403

    def test_unknown_tool_rejected(self, auth_client, domain):
        resp = post_json(auth_client, "/api/scans/start/", {
            "domain": "example.com",
            "schedule_type": "now",
            "tools": ["not_a_real_tool"],
        })
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Subscan gate — active tools against a parent domain need authorization
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSubscanAuthorizationGate:
    def _parent(self):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
        )

    def test_active_subscan_on_unauthorized_domain_rejected(self, auth_client, domain):
        parent = self._parent()  # example.com, no DomainAuthorization
        resp = post_json(
            auth_client, f"/api/scans/{parent.uuid}/subscan/",
            {"tools": ["nmap"]},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["message"] == "Domain is not authorized for scanning"

    def test_passive_subscan_on_unauthorized_domain_allowed(self, auth_client, domain):
        parent = self._parent()
        fake_session = type("S", (), {"uuid": "sub-uuid-1", "id": 9})()
        with patch("apps.core.engine.scans.tasks.run_scan_task"), \
             patch("apps.core.engine.scans.pipeline.create_subscan_session", return_value=fake_session):
            resp = post_json(
                auth_client, f"/api/scans/{parent.uuid}/subscan/",
                {"tools": ["subfinder", "dnsx"]},
            )
        assert resp.status_code == 200, resp.content
        assert resp.json()["uuid"] == "sub-uuid-1"

    def test_active_subscan_allowed_when_authorized(self, auth_client, domain):
        from apps.core.data.domains.models import DomainAuthorization
        DomainAuthorization.objects.create(
            domain=domain, auth_type="owner",
            authorized_at=datetime.date(2026, 1, 15), authorized_by="Alice",
        )
        parent = self._parent()
        fake_session = type("S", (), {"uuid": "sub-uuid-2", "id": 10})()
        with patch("apps.core.engine.scans.tasks.run_scan_task"), \
             patch("apps.core.engine.scans.pipeline.create_subscan_session", return_value=fake_session):
            resp = post_json(
                auth_client, f"/api/scans/{parent.uuid}/subscan/",
                {"tools": ["nmap"]},
            )
        assert resp.status_code == 200, resp.content
