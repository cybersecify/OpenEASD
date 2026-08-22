"""Tests for silent-block coverage counting, coverage-regression flagging, and
partial scan status (the 'silent degradation' fixes)."""

import pytest

from apps.core.scans.pipeline import (
    _compute_coverage, _check_coverage_regression, _finalize_session,
)


def _session(**kw):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", **kw)


def _httpx_url(session, host, reachability=""):
    from apps.core.web_assets.models import URL
    return URL.objects.create(
        session=session, url=f"https://{host}:443", host=host, port_number=443,
        scheme="https", reachability=reachability, source="httpx",
    )


@pytest.mark.django_db
class TestSilentBlockCounting:
    def test_all_probes_dropped_counts_as_blocked(self):
        # httpx probed 10 targets, 0 came back (silent block) -> blocked = 10.
        s = _session(endpoints_probed=10)
        _compute_coverage(s)
        assert s.endpoints_probed == 10
        assert s.endpoints_blocked == 10

    def test_partial_reach(self):
        # probed 10, 8 responded cleanly -> 2 unreachable.
        s = _session(endpoints_probed=10)
        for i in range(8):
            _httpx_url(s, f"h{i}.example.com", reachability="reached")
        _compute_coverage(s)
        assert s.endpoints_blocked == 2

    def test_interfered_counts_as_blocked(self):
        s = _session(endpoints_probed=3)
        _httpx_url(s, "a.example.com", reachability="reached")
        _httpx_url(s, "b.example.com", reachability="blocked")
        _httpx_url(s, "c.example.com", reachability="challenged")
        _compute_coverage(s)
        assert s.endpoints_blocked == 2  # blocked + challenged


@pytest.mark.django_db
class TestCoverageRegression:
    def test_high_block_ratio_flags(self):
        from apps.core.findings.models import Finding
        s = _session(endpoints_probed=10, endpoints_blocked=10)
        _check_coverage_regression(s)
        f = Finding.objects.filter(session=s, check_type="coverage_regression")
        assert f.count() == 1
        assert "unreachable" in f.first().description.lower()

    def test_findings_drop_flags(self):
        from apps.core.findings.models import Finding
        prev = _session(status="completed", total_findings=50)
        cur = _session(total_findings=10)
        _check_coverage_regression(cur)
        assert Finding.objects.filter(session=cur, check_type="coverage_regression").exists()

    def test_stable_scan_no_flag(self):
        from apps.core.findings.models import Finding
        _session(status="completed", total_findings=50)
        cur = _session(total_findings=48, endpoints_probed=10, endpoints_blocked=1)
        _check_coverage_regression(cur)
        assert not Finding.objects.filter(session=cur, check_type="coverage_regression").exists()

    def test_no_previous_and_reachable_no_flag(self):
        from apps.core.findings.models import Finding
        cur = _session(total_findings=3, endpoints_probed=4, endpoints_blocked=1)
        _check_coverage_regression(cur)
        assert not Finding.objects.filter(session=cur, check_type="coverage_regression").exists()


@pytest.mark.django_db
class TestPartialStatus:
    def _run(self, session, status):
        from apps.core.workflows.models import Workflow, WorkflowRun
        wf = Workflow.objects.create(name="wf")
        return WorkflowRun.objects.create(workflow=wf, session=session, status=status)

    def test_partial_when_a_tool_failed(self):
        s = _session()
        self._run(s, "partial")
        _finalize_session(s)
        s.refresh_from_db()
        assert s.status == "partial"

    def test_completed_when_all_ok(self):
        s = _session()
        self._run(s, "completed")
        _finalize_session(s)
        s.refresh_from_db()
        assert s.status == "completed"

    def test_failed_run_marks_partial(self):
        s = _session()
        self._run(s, "failed")
        _finalize_session(s)
        s.refresh_from_db()
        assert s.status == "partial"
