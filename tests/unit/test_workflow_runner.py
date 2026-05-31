"""
Unit tests for apps/core/workflows/runner.py and models.py

Tests run_workflow step execution, cancellation, error handling,
partial failure, and service_detection injection.
"""

from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from apps.core.workflows.models import Workflow, WorkflowRun, WorkflowStep, WorkflowStepResult
from apps.core.workflows.runner import run_workflow


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def session(db):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(
        domain="runner.example.com", scan_type="full", status="running"
    )


@pytest.fixture
def workflow(db):
    wf = Workflow.objects.create(name="Runner Test Workflow")
    WorkflowStep.objects.create(workflow=wf, tool="subfinder", order=1, enabled=True)
    WorkflowStep.objects.create(workflow=wf, tool="dnsx",      order=2, enabled=True)
    return wf


@pytest.fixture
def run(db, workflow, session):
    return WorkflowRun.objects.create(workflow=workflow, session=session)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_runner(return_value=None):
    """Return a mock tool runner that returns a given value."""
    return MagicMock(return_value=return_value)


def _patch_get_runner(tool_map):
    """Patch _get_runner to return the mock from tool_map by tool name."""
    def side_effect(tool_name):
        if tool_name in tool_map:
            return tool_map[tool_name]
        # service_detection gets a no-op by default
        return MagicMock(return_value=None)
    return patch("apps.core.workflows.runner._get_runner", side_effect=side_effect)


# ---------------------------------------------------------------------------
# run_workflow — happy path
# ---------------------------------------------------------------------------

class TestRunWorkflowSuccess:
    def test_run_status_becomes_completed(self, db, run):
        with _patch_get_runner({"subfinder": _mock_runner(), "dnsx": _mock_runner()}):
            run_workflow(run.id)

        run.refresh_from_db()
        assert run.status == "completed"
        assert run.started_at is not None
        assert run.finished_at is not None

    def test_all_steps_recorded_as_completed(self, db, run):
        with _patch_get_runner({"subfinder": _mock_runner(), "dnsx": _mock_runner()}):
            run_workflow(run.id)

        results = WorkflowStepResult.objects.filter(run=run).order_by("order")
        tool_names = [r.tool for r in results]
        assert "subfinder" in tool_names
        assert "dnsx" in tool_names
        for r in results:
            assert r.status in ("completed", "skipped")  # service_detection may be injected

    def test_step_findings_count_zero_for_asset_producing_tools(self, db, run):
        """Subfinder/dnsx/naabu/httpx return assets (Subdomain/IPAddress/Port/URL),
        not Findings. Their step_result.findings_count must stay 0 to avoid
        falsely claiming "subfinder: 10 findings" in API responses.
        """
        with _patch_get_runner({
            "subfinder": _mock_runner(["sub1.example.com", "sub2.example.com"]),
            "dnsx":      _mock_runner([]),
        }):
            run_workflow(run.id)

        subfinder_result = WorkflowStepResult.objects.get(run=run, tool="subfinder")
        # subfinder.apps.SubfinderConfig.tool_meta has produces_findings=False
        assert subfinder_result.findings_count == 0
        assert subfinder_result.status == "completed"

    def test_step_findings_count_populated_for_finding_producing_tools(self, db, session):
        """nmap (and domain_security, web_checker, etc.) DO return Finding rows.
        Their findings_count must reflect the returned list length so API
        callers can see per-tool finding totals.
        """
        wf = Workflow.objects.create(name="Finding Tool Test")
        WorkflowStep.objects.create(workflow=wf, tool="nmap", order=1, enabled=True)
        nmap_run = WorkflowRun.objects.create(workflow=wf, session=session)

        with _patch_get_runner({"nmap": _mock_runner(["cve-1", "cve-2", "cve-3"])}):
            run_workflow(nmap_run.id)

        nmap_result = WorkflowStepResult.objects.get(run=nmap_run, tool="nmap")
        # nmap.apps.NmapConfig.tool_meta has produces_findings=True
        assert nmap_result.findings_count == 3
        assert nmap_result.status == "completed"

    def test_step_findings_count_for_none_return(self, db, run):
        with _patch_get_runner({"subfinder": _mock_runner(None), "dnsx": _mock_runner(None)}):
            run_workflow(run.id)

        r = WorkflowStepResult.objects.get(run=run, tool="subfinder")
        assert r.findings_count == 0

    def test_each_step_has_timing(self, db, run):
        with _patch_get_runner({"subfinder": _mock_runner(), "dnsx": _mock_runner()}):
            run_workflow(run.id)

        for r in WorkflowStepResult.objects.filter(run=run):
            assert r.started_at is not None
            assert r.finished_at is not None


# ---------------------------------------------------------------------------
# run_workflow — service_detection injection
# ---------------------------------------------------------------------------

class TestServiceDetectionInjection:
    def test_service_detection_injected_when_missing(self, db, run, workflow):
        # workflow has subfinder + dnsx but NO service_detection
        tools_used = []

        def track_runner(tool_name):
            tools_used.append(tool_name)
            return MagicMock(return_value=None)

        with patch("apps.core.workflows.runner._get_runner", side_effect=track_runner):
            run_workflow(run.id)

        assert "service_detection" in tools_used

    def test_service_detection_inserted_after_naabu(self, db, session):
        wf = Workflow.objects.create(name="Naabu Workflow")
        WorkflowStep.objects.create(workflow=wf, tool="subfinder",  order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="naabu",      order=2, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="httpx",      order=3, enabled=True)
        run = WorkflowRun.objects.create(workflow=wf, session=session)

        tools_used = []

        def track_runner(tool_name):
            tools_used.append(tool_name)
            return MagicMock(return_value=None)

        with patch("apps.core.workflows.runner._get_runner", side_effect=track_runner):
            run_workflow(run.id)

        naabu_idx = tools_used.index("naabu")
        sd_idx = tools_used.index("service_detection")
        assert sd_idx == naabu_idx + 1

    def test_service_detection_not_duplicated_when_already_in_workflow(self, db, session):
        wf = Workflow.objects.create(name="SD Workflow")
        WorkflowStep.objects.create(workflow=wf, tool="naabu",             order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="service_detection", order=2, enabled=True)
        run = WorkflowRun.objects.create(workflow=wf, session=session)

        tools_used = []

        def track_runner(tool_name):
            tools_used.append(tool_name)
            return MagicMock(return_value=None)

        with patch("apps.core.workflows.runner._get_runner", side_effect=track_runner):
            run_workflow(run.id)

        assert tools_used.count("service_detection") == 1


# ---------------------------------------------------------------------------
# run_workflow — step failure
# ---------------------------------------------------------------------------

class TestRunWorkflowStepFailure:
    def test_failed_step_marks_run_as_partial(self, db, run):
        def failing_runner(tool_name):
            if tool_name == "subfinder":
                m = MagicMock(side_effect=RuntimeError("binary not found"))
                return m
            return MagicMock(return_value=None)

        with patch("apps.core.workflows.runner._get_runner", side_effect=failing_runner):
            run_workflow(run.id)

        run.refresh_from_db()
        assert run.status == "partial"

    def test_failed_step_records_error_message(self, db, run):
        def failing_runner(tool_name):
            if tool_name == "subfinder":
                return MagicMock(side_effect=RuntimeError("tool timed out"))
            return MagicMock(return_value=None)

        with patch("apps.core.workflows.runner._get_runner", side_effect=failing_runner):
            run_workflow(run.id)

        r = WorkflowStepResult.objects.get(run=run, tool="subfinder")
        assert r.status == "failed"
        assert "tool timed out" in r.error

    def test_remaining_steps_still_run_after_failure(self, db, run):
        def failing_runner(tool_name):
            if tool_name == "subfinder":
                return MagicMock(side_effect=RuntimeError("oops"))
            return MagicMock(return_value=None)

        with patch("apps.core.workflows.runner._get_runner", side_effect=failing_runner):
            run_workflow(run.id)

        # dnsx should still have run
        dnsx_result = WorkflowStepResult.objects.get(run=run, tool="dnsx")
        assert dnsx_result.status == "completed"

    def test_all_steps_fail_marks_run_as_partial(self, db, run):
        def always_fail(tool_name):
            return MagicMock(side_effect=Exception("fail"))

        with patch("apps.core.workflows.runner._get_runner", side_effect=always_fail):
            run_workflow(run.id)

        run.refresh_from_db()
        assert run.status == "partial"


# ---------------------------------------------------------------------------
# run_workflow — cancellation
# ---------------------------------------------------------------------------

class TestRunWorkflowCancellation:
    def test_cancelled_session_stops_at_next_step(self, db, session, workflow):
        run = WorkflowRun.objects.create(workflow=workflow, session=session)

        call_count = [0]

        def cancel_after_first(tool_name):
            def runner(sess):
                call_count[0] += 1
                # Cancel session after the first tool runs
                from apps.core.scans.models import ScanSession
                ScanSession.objects.filter(pk=sess.pk).update(status="cancelled")
                return []
            return runner

        with patch("apps.core.workflows.runner._get_runner", side_effect=cancel_after_first):
            run_workflow(run.id)

        # Only the first step should have fully run; second should be skipped
        results = WorkflowStepResult.objects.filter(run=run).order_by("order")
        statuses = [r.status for r in results]
        assert "skipped" in statuses

    def test_cancelled_step_has_skipped_status(self, db, session):
        wf = Workflow.objects.create(name="Cancel Workflow")
        WorkflowStep.objects.create(workflow=wf, tool="subfinder", order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="dnsx",      order=2, enabled=True)
        run = WorkflowRun.objects.create(workflow=wf, session=session)

        # Pre-cancel the session so first check sees cancelled
        from apps.core.scans.models import ScanSession
        ScanSession.objects.filter(pk=session.pk).update(status="cancelled")

        with patch("apps.core.workflows.runner._get_runner", return_value=MagicMock(return_value=[])):
            run_workflow(run.id)

        results = WorkflowStepResult.objects.filter(run=run)
        assert all(r.status == "skipped" for r in results)


# ---------------------------------------------------------------------------
# Workflow model
# ---------------------------------------------------------------------------

class TestWorkflowModel:
    def test_enabled_tools_returns_only_enabled_steps(self, db):
        wf = Workflow.objects.create(name="Model Test")
        WorkflowStep.objects.create(workflow=wf, tool="subfinder", order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="dnsx",      order=2, enabled=False)
        WorkflowStep.objects.create(workflow=wf, tool="naabu",     order=3, enabled=True)

        tools = wf.enabled_tools()
        assert "subfinder" in tools
        assert "naabu" in tools
        assert "dnsx" not in tools

    def test_enabled_tools_ordered_by_order_field(self, db):
        wf = Workflow.objects.create(name="Order Test")
        WorkflowStep.objects.create(workflow=wf, tool="httpx",     order=8, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="subfinder", order=2, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="naabu",     order=4, enabled=True)

        tools = wf.enabled_tools()
        assert tools == ["subfinder", "naabu", "httpx"]

    def test_is_default_enforces_single_default(self, db):
        wf1 = Workflow.objects.create(name="Default 1", is_default=True)
        wf2 = Workflow.objects.create(name="Default 2", is_default=True)
        wf1.refresh_from_db()
        assert not wf1.is_default  # demoted
        assert wf2.is_default

    def test_step_unique_together(self, db):
        from django.db import IntegrityError
        wf = Workflow.objects.create(name="Unique Test")
        WorkflowStep.objects.create(workflow=wf, tool="subfinder", order=1)
        with pytest.raises(IntegrityError):
            WorkflowStep.objects.create(workflow=wf, tool="subfinder", order=2)


# ---------------------------------------------------------------------------
# WorkflowStepResult
# ---------------------------------------------------------------------------

class TestWorkflowStepResult:
    def test_duration_seconds(self, db, run):
        from django.utils import timezone as tz
        start = tz.now()
        end = start + timezone.timedelta(seconds=5)
        sr = WorkflowStepResult.objects.create(
            run=run, tool="subfinder", order=1,
            started_at=start, finished_at=end,
        )
        assert sr.duration_seconds == pytest.approx(5.0, abs=0.1)

    def test_duration_seconds_none_when_not_finished(self, db, run):
        sr = WorkflowStepResult.objects.create(run=run, tool="subfinder", order=1)
        assert sr.duration_seconds is None


# ---------------------------------------------------------------------------
# _group_tools_by_phase
# ---------------------------------------------------------------------------

class TestGroupToolsByPhase:
    """Pure function — no DB needed."""

    def test_single_tool_per_phase_returns_singleton_groups(self):
        from apps.core.workflows.runner import _group_tools_by_phase
        # subfinder=phase2, dnsx=phase3, naabu=phase4 — each in its own phase
        groups = _group_tools_by_phase(["subfinder", "dnsx", "naabu"])
        assert groups == [["subfinder"], ["dnsx"], ["naabu"]]

    def test_multi_tool_phase_grouped_together(self):
        from apps.core.workflows.runner import _group_tools_by_phase
        # nmap, tls_checker, ssh_checker, nuclei_network are all phase 7
        groups = _group_tools_by_phase(["nmap", "tls_checker", "ssh_checker", "nuclei_network"])
        assert len(groups) == 1
        assert set(groups[0]) == {"nmap", "tls_checker", "ssh_checker", "nuclei_network"}

    def test_mixed_phases_split_correctly(self):
        from apps.core.workflows.runner import _group_tools_by_phase
        # subfinder (phase 2) + nmap (phase 7): two separate groups
        groups = _group_tools_by_phase(["subfinder", "nmap"])
        assert groups == [["subfinder"], ["nmap"]]

    def test_preserves_intra_phase_order(self):
        from apps.core.workflows.runner import _group_tools_by_phase
        # Phase 7 tools — order within group must match input order
        tools = ["ssh_checker", "nmap", "tls_checker", "nuclei_network"]
        groups = _group_tools_by_phase(tools)
        assert len(groups) == 1
        assert groups[0] == ["ssh_checker", "nmap", "tls_checker", "nuclei_network"]

    def test_unknown_tool_defaults_to_phase_99(self):
        from apps.core.workflows.runner import _group_tools_by_phase
        # An unregistered tool should sort last (phase 99)
        groups = _group_tools_by_phase(["subfinder", "unknown_tool"])
        assert groups[0] == ["subfinder"]
        assert groups[1] == ["unknown_tool"]

    def test_empty_list_returns_empty(self):
        from apps.core.workflows.runner import _group_tools_by_phase
        assert _group_tools_by_phase([]) == []


# ---------------------------------------------------------------------------
# Phase-parallel execution
# ---------------------------------------------------------------------------

class TestPhaseParallelExecution:

    def test_same_phase_tools_run_concurrently(self, transactional_db):
        """Phase 7 tools (nmap + tls_checker) must run concurrently.

        Uses threading.Barrier(2): each runner calls barrier.wait() before
        returning. If they run serially the barrier is never satisfied, causing
        BrokenBarrierError inside the thread, which runner.py records as a
        'failed' step. So if run.status == 'completed', they ran in parallel.
        """
        import threading
        from apps.core.scans.models import ScanSession

        barrier = threading.Barrier(2, timeout=5)
        session = ScanSession.objects.create(
            domain="parallel.example.com", scan_type="full", status="running"
        )
        wf = Workflow.objects.create(name="Parallel Phase 7")
        WorkflowStep.objects.create(workflow=wf, tool="nmap",        order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="tls_checker", order=2, enabled=True)
        run = WorkflowRun.objects.create(workflow=wf, session=session)

        def barrier_runner(tool_name):
            if tool_name == "service_detection":
                return MagicMock(return_value=None)
            def runner(sess):
                barrier.wait()
                return []
            return runner

        with patch("apps.core.workflows.runner._get_runner", side_effect=barrier_runner):
            run_workflow(run.id)

        run.refresh_from_db()
        assert run.status == "completed", (
            "Run is not 'completed' — tools likely ran serially (barrier never satisfied)"
        )

    def test_phase_boundary_respected(self, transactional_db):
        """All phase-7 tools must finish before any phase-10 tool starts.

        Uses threading.Event: nmap and tls_checker set phase7_done only after both
        have run (checked via a counter). nuclei asserts phase7_done is set before
        it proceeds. If phase 10 started before phase 7 finished, the assertion
        inside nuclei's runner would fail.
        """
        import threading
        from apps.core.scans.models import ScanSession

        phase7_done = threading.Event()
        phase7_count = [0]
        count_lock = threading.Lock()

        session = ScanSession.objects.create(
            domain="boundary.example.com", scan_type="full", status="running"
        )
        wf = Workflow.objects.create(name="Phase Boundary Multi")
        # Phase 7: nmap + tls_checker (parallel within phase)
        WorkflowStep.objects.create(workflow=wf, tool="nmap",        order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="tls_checker", order=2, enabled=True)
        # Phase 10: nuclei (must start after phase 7 fully done)
        WorkflowStep.objects.create(workflow=wf, tool="nuclei",      order=3, enabled=True)
        run = WorkflowRun.objects.create(workflow=wf, session=session)

        def make_runner(tool_name):
            def runner(sess):
                if tool_name == "service_detection":
                    return []
                if tool_name in ("nmap", "tls_checker"):
                    with count_lock:
                        phase7_count[0] += 1
                        if phase7_count[0] == 2:
                            phase7_done.set()
                    return []
                if tool_name == "nuclei":
                    assert phase7_done.is_set(), (
                        "nuclei started before both phase-7 tools finished"
                    )
                    return []
                return []
            return runner

        with patch("apps.core.workflows.runner._get_runner", side_effect=make_runner):
            run_workflow(run.id)

        run.refresh_from_db()
        assert run.status == "completed"
        assert phase7_done.is_set()

    def test_parallel_tool_failure_does_not_cancel_sibling(self, transactional_db):
        """If nmap fails, tls_checker (same phase 7) must still run to completion."""
        import threading
        from apps.core.scans.models import ScanSession

        # Use a barrier so we know both tools started
        started = threading.Barrier(2, timeout=5)
        session = ScanSession.objects.create(
            domain="sibling.example.com", scan_type="full", status="running"
        )
        wf = Workflow.objects.create(name="Sibling Failure")
        WorkflowStep.objects.create(workflow=wf, tool="nmap",        order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="tls_checker", order=2, enabled=True)
        run = WorkflowRun.objects.create(workflow=wf, session=session)

        def make_runner(tool_name):
            if tool_name == "service_detection":
                return MagicMock(return_value=None)
            def runner(sess):
                started.wait()          # both must start before either proceeds
                if tool_name == "nmap":
                    raise RuntimeError("nmap timed out")
                return ["finding-1"]
            return runner

        with patch("apps.core.workflows.runner._get_runner", side_effect=make_runner):
            run_workflow(run.id)

        run.refresh_from_db()
        assert run.status == "partial"   # nmap failed → partial, not cancelled
        tls_result = WorkflowStepResult.objects.get(run=run, tool="tls_checker")
        assert tls_result.status == "completed"
        nmap_result = WorkflowStepResult.objects.get(run=run, tool="nmap")
        assert nmap_result.status == "failed"

    def test_cancellation_stops_between_phases_not_mid_phase(self, transactional_db):
        """When session is cancelled during phase 7, all phase 7 tools still finish.
        Phase 10 tools (nuclei, web_checker) must be skipped.
        """
        import threading
        from apps.core.scans.models import ScanSession

        both_started = threading.Barrier(2, timeout=5)
        session = ScanSession.objects.create(
            domain="cancel.example.com", scan_type="full", status="running"
        )
        wf = Workflow.objects.create(name="Mid-Phase Cancel")
        WorkflowStep.objects.create(workflow=wf, tool="nmap",        order=1, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="tls_checker", order=2, enabled=True)
        WorkflowStep.objects.create(workflow=wf, tool="nuclei",      order=3, enabled=True)
        run = WorkflowRun.objects.create(workflow=wf, session=session)

        def make_runner(tool_name):
            if tool_name == "service_detection":
                return MagicMock(return_value=None)
            def runner(sess):
                both_started.wait()
                # nmap cancels the session mid-phase
                if tool_name == "nmap":
                    ScanSession.objects.filter(pk=sess.pk).update(status="cancelled")
                return []
            return runner

        with patch("apps.core.workflows.runner._get_runner", side_effect=make_runner):
            run_workflow(run.id)

        run.refresh_from_db()
        assert run.status == "cancelled"

        # Both phase-7 tools ran (cancellation detected between phases, not mid-phase)
        assert WorkflowStepResult.objects.get(run=run, tool="nmap").status == "completed"
        assert WorkflowStepResult.objects.get(run=run, tool="tls_checker").status == "completed"
        # Phase-10 tool was skipped
        assert WorkflowStepResult.objects.get(run=run, tool="nuclei").status == "skipped"
