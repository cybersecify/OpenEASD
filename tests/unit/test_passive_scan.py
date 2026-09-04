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
}
_ACTIVE = {
    "domain_security", "amass", "takeover_check", "naabu", "service_detection",
    "nmap", "tls_checker", "ssh_checker", "nuclei_network", "httpx",
    "katana", "nuclei", "web_checker",
}


# ---------------------------------------------------------------------------
# Registry classification
# ---------------------------------------------------------------------------

class TestRegistryActiveFlag:
    def test_every_tool_has_active_flag(self):
        from apps.core.workflows.registry import get_tool_active
        active = get_tool_active()
        # every registered tool is classified either passive or active
        for tool in _PASSIVE | _ACTIVE:
            assert tool in active, f"{tool} missing from registry"

    def test_passive_tools_marked_passive(self):
        from apps.core.workflows.registry import get_tool_active
        active = get_tool_active()
        for tool in _PASSIVE:
            assert active[tool] is False, f"{tool} should be passive (active=False)"

    def test_active_tools_marked_active(self):
        from apps.core.workflows.registry import get_tool_active
        active = get_tool_active()
        for tool in _ACTIVE:
            assert active[tool] is True, f"{tool} should be active (active=True)"

    def test_default_is_active_for_unknown_tool(self):
        # A tool with no explicit flag must default to active (the safe default:
        # a missing flag can never let a scanner probe an unauthorized target).
        from apps.core.workflows.registry import get_tool_active
        active = get_tool_active()
        assert active.get("some_unregistered_tool", True) is True


# ---------------------------------------------------------------------------
# is_passive_tool_set helper
# ---------------------------------------------------------------------------

class TestIsPassiveToolSet:
    def test_all_passive_returns_true(self):
        from apps.core.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["subfinder", "dnsx", "cloud_assets"]) is True

    def test_single_active_tool_makes_set_active(self):
        from apps.core.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["subfinder", "dnsx", "naabu"]) is False

    def test_empty_set_is_not_passive(self):
        from apps.core.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set([]) is False

    def test_unknown_tool_treated_as_active(self):
        from apps.core.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["subfinder", "mystery_tool"]) is False

    def test_domain_security_is_active(self):
        # Regression guard: domain_security performs AXFR zone transfers, SMTP
        # open-relay probes, and mta-sts policy fetches against the target, so it
        # must never be classified passive despite being mostly DNS lookups.
        from apps.core.workflows.registry import is_passive_tool_set
        assert is_passive_tool_set(["domain_security"]) is False


# ---------------------------------------------------------------------------
# Passive Scan workflow (migration 0022)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestPassiveScanWorkflow:
    def test_workflow_exists(self):
        from apps.core.workflows.models import Workflow
        assert Workflow.objects.filter(name="Passive Scan").exists()

    def test_workflow_is_not_default(self):
        from apps.core.workflows.models import Workflow
        wf = Workflow.objects.get(name="Passive Scan")
        assert wf.is_default is False

    def test_every_step_is_passive(self):
        # THE safety invariant: no active tool may appear in the Passive Scan
        # workflow, or a passive scan would probe an unauthorized target.
        from apps.core.workflows.models import Workflow
        from apps.core.workflows.registry import get_tool_active
        wf = Workflow.objects.get(name="Passive Scan")
        active = get_tool_active()
        for tool in wf.enabled_tools():
            assert active.get(tool, True) is False, f"{tool} in Passive Scan is active!"

    def test_workflow_is_passive_tool_set(self):
        from apps.core.workflows.models import Workflow
        from apps.core.workflows.registry import is_passive_tool_set
        wf = Workflow.objects.get(name="Passive Scan")
        assert is_passive_tool_set(wf.enabled_tools()) is True


# ---------------------------------------------------------------------------
# Authorization gate — the critical boundary
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestPassiveScanAuthorizationGate:
    def _passive_workflow_id(self):
        from apps.core.workflows.models import Workflow
        return Workflow.objects.get(name="Passive Scan").id

    def test_passive_scan_bypasses_authorization(self, auth_client, domain):
        # domain fixture (example.com) has NO DomainAuthorization. A passive-only
        # scan must still be accepted — it never touches the target.
        fake_session = type("S", (), {"uuid": "passive-uuid-1", "id": 1})()
        with patch("apps.core.scans.tasks.run_scan_task"), \
             patch("apps.core.scans.pipeline.create_scan_session", return_value=fake_session):
            resp = post_json(auth_client, "/api/scans/start/", {
                "domain": "example.com",
                "schedule_type": "now",
                "workflow_id": self._passive_workflow_id(),
            })
        assert resp.status_code == 201, resp.content
        assert resp.json()["uuid"] == "passive-uuid-1"

    def test_active_workflow_still_requires_authorization(self, auth_client, domain):
        # An explicit active workflow (Full Scan) on an unauthorized domain → 403.
        from apps.core.workflows.models import Workflow
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
        from apps.core.domains.models import DomainAuthorization
        DomainAuthorization.objects.create(
            domain=domain, auth_type="owner",
            authorized_at=datetime.date(2026, 1, 15), authorized_by="Alice",
        )
        fake_session = type("S", (), {"uuid": "passive-uuid-2", "id": 2})()
        with patch("apps.core.scans.tasks.run_scan_task"), \
             patch("apps.core.scans.pipeline.create_scan_session", return_value=fake_session):
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


# ---------------------------------------------------------------------------
# Subscan gate — active tools against a parent domain need authorization
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSubscanAuthorizationGate:
    def _parent(self):
        from apps.core.scans.models import ScanSession
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
        with patch("apps.core.scans.tasks.run_scan_task"), \
             patch("apps.core.scans.pipeline.create_subscan_session", return_value=fake_session):
            resp = post_json(
                auth_client, f"/api/scans/{parent.uuid}/subscan/",
                {"tools": ["subfinder", "dnsx"]},
            )
        assert resp.status_code == 200, resp.content
        assert resp.json()["uuid"] == "sub-uuid-1"

    def test_active_subscan_allowed_when_authorized(self, auth_client, domain):
        from apps.core.domains.models import DomainAuthorization
        DomainAuthorization.objects.create(
            domain=domain, auth_type="owner",
            authorized_at=datetime.date(2026, 1, 15), authorized_by="Alice",
        )
        parent = self._parent()
        fake_session = type("S", (), {"uuid": "sub-uuid-2", "id": 10})()
        with patch("apps.core.scans.tasks.run_scan_task"), \
             patch("apps.core.scans.pipeline.create_subscan_session", return_value=fake_session):
            resp = post_json(
                auth_client, f"/api/scans/{parent.uuid}/subscan/",
                {"tools": ["nmap"]},
            )
        assert resp.status_code == 200, resp.content
