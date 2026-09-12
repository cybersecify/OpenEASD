"""Tests for the H4/H9 watchdog↔DBOS reconcile — reap_stuck_scans cancels the
reaped scan's DBOS workflow inline, and the helper is safe/idempotent."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from apps.core.engine.scans.models import ScanSession
from apps.core.engine.scheduler.scheduler import (
    SCAN_TIMEOUT_MINUTES,
    _cancel_workflows_for_sessions,
    reap_stuck_scans,
)

pytestmark = pytest.mark.django_db


def _wf(workflow_id, dedup):
    return SimpleNamespace(workflow_id=workflow_id, deduplication_id=dedup)


def _fake_client(workflows):
    c = MagicMock()
    c.list_workflows.return_value = workflows
    return c


def _patch_client(client):
    return patch("apps.core.engine.durable.client.get_client", return_value=client)


def _stuck_running(domain):
    s = ScanSession.objects.create(domain=domain, status="running")
    ScanSession.objects.filter(id=s.id).update(
        start_time=timezone.now() - timedelta(minutes=SCAN_TIMEOUT_MINUTES + 10)
    )
    return s


class TestCancelHelper:
    def test_cancels_only_matching_sessions(self):
        client = _fake_client([_wf("wf-1", "scan-1"), _wf("wf-2", "scan-2"), _wf("wf-3", "scan-3")])
        with _patch_client(client):
            n = _cancel_workflows_for_sessions([1, 3])
        assert n == 2
        called = {c.args[0] for c in client.cancel_workflow.call_args_list}
        assert called == {"wf-1", "wf-3"}

    def test_empty_is_noop(self):
        client = _fake_client([])
        with _patch_client(client):
            assert _cancel_workflows_for_sessions([]) == 0
        client.list_workflows.assert_not_called()

    def test_list_failure_swallowed(self):
        client = MagicMock()
        client.list_workflows.side_effect = RuntimeError("dbos down")
        with _patch_client(client):
            assert _cancel_workflows_for_sessions([1]) == 0

    def test_cancel_failure_does_not_abort(self):
        client = _fake_client([_wf("wf-1", "scan-1"), _wf("wf-2", "scan-2")])
        client.cancel_workflow.side_effect = [RuntimeError("boom"), None]
        with _patch_client(client):
            n = _cancel_workflows_for_sessions([1, 2])
        assert n == 1
        assert client.cancel_workflow.call_count == 2


class TestReapCancelsWorkflow:
    def test_reaping_cancels_the_scans_workflow(self):
        s = _stuck_running("ex.com")
        client = _fake_client([_wf("wf-x", f"scan-{s.id}")])
        with _patch_client(client):
            reaped = reap_stuck_scans()
        assert reaped == 1
        s.refresh_from_db()
        assert s.status in ("failed", "partial")
        client.cancel_workflow.assert_called_once_with("wf-x")

    def test_reap_with_no_matching_workflow_is_fine(self):
        _stuck_running("ex.com")
        client = _fake_client([_wf("wf-other", "scan-999")])  # unrelated
        with _patch_client(client):
            reaped = reap_stuck_scans()
        assert reaped == 1
        client.cancel_workflow.assert_not_called()
