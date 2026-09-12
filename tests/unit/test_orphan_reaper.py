"""Tests for the orphaned-workflow reaper (H8).

reap_orphaned_scan_workflows cancels ENQUEUED/PENDING run_scan DBOS workflows
whose ScanSession is terminal or missing (phantoms holding a scans-queue slot),
and never touches a workflow whose session is still pending/running.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from apps.core.engine.scans.models import ScanSession
from apps.core.engine.scheduler.scheduler import reap_orphaned_scan_workflows

pytestmark = pytest.mark.django_db


def _wf(workflow_id, dedup):
    """A minimal stand-in for a DBOS WorkflowStatus."""
    return SimpleNamespace(workflow_id=workflow_id, deduplication_id=dedup)


def _fake_client(workflows):
    client = MagicMock()
    client.list_workflows.return_value = workflows
    return client


def _patch_client(client):
    # reap_orphaned_scan_workflows imports get_client from this module at call time.
    return patch("apps.core.engine.durable.client.get_client", return_value=client)


def test_terminal_session_workflow_is_cancelled():
    s = ScanSession.objects.create(domain="ex.com", status="failed")
    client = _fake_client([_wf("wf-1", f"scan-{s.id}")])
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows()
    assert [r[0] for r in reaped] == ["wf-1"]
    client.cancel_workflow.assert_called_once_with("wf-1")


@pytest.mark.parametrize("status", ["pending", "running"])
def test_live_session_workflow_is_kept(status):
    s = ScanSession.objects.create(domain="ex.com", status=status)
    client = _fake_client([_wf("wf-live", f"scan-{s.id}")])
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows()
    assert reaped == []
    client.cancel_workflow.assert_not_called()


def test_missing_session_workflow_is_cancelled():
    # dedup points at a session id that does not exist → orphan.
    client = _fake_client([_wf("wf-gone", "scan-999999")])
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows()
    assert reaped == [("wf-gone", "scan-999999", "missing")]
    client.cancel_workflow.assert_called_once_with("wf-gone")


def test_unmappable_dedup_is_left_alone():
    client = _fake_client([_wf("wf-x", "not-a-scan-handle")])
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows()
    assert reaped == []
    client.cancel_workflow.assert_not_called()


def test_dry_run_lists_but_cancels_nothing():
    s = ScanSession.objects.create(domain="ex.com", status="cancelled")
    client = _fake_client([_wf("wf-2", f"scan-{s.id}")])
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows(apply=False)
    assert [r[0] for r in reaped] == ["wf-2"]
    client.cancel_workflow.assert_not_called()


def test_mixed_batch_only_terminal_cancelled():
    live = ScanSession.objects.create(domain="ex.com", status="running")
    dead = ScanSession.objects.create(domain="ex.com", status="completed")
    client = _fake_client([
        _wf("wf-live", f"scan-{live.id}"),
        _wf("wf-dead", f"scan-{dead.id}"),
    ])
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows()
    assert [r[0] for r in reaped] == ["wf-dead"]
    client.cancel_workflow.assert_called_once_with("wf-dead")


def test_list_failure_is_swallowed():
    client = MagicMock()
    client.list_workflows.side_effect = RuntimeError("dbos down")
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows()
    assert reaped == []  # fail-graceful — never raises inside the watchdog


def test_cancel_failure_does_not_abort_batch():
    s1 = ScanSession.objects.create(domain="a.com", status="failed")
    s2 = ScanSession.objects.create(domain="b.com", status="failed")
    client = _fake_client([_wf("wf-a", f"scan-{s1.id}"), _wf("wf-b", f"scan-{s2.id}")])
    client.cancel_workflow.side_effect = [RuntimeError("boom"), None]
    with _patch_client(client):
        reaped = reap_orphaned_scan_workflows()
    # both are reported as phantoms; the first cancel failing doesn't stop the second
    assert {r[0] for r in reaped} == {"wf-a", "wf-b"}
    assert client.cancel_workflow.call_count == 2
