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
        _session(status="completed", total_findings=50)  # baseline the check compares against
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

    def test_different_workflow_not_compared(self):
        # A Passive Scan (fewer tools) must NOT be diffed against a prior Full
        # Scan baseline — that always looks like a collapse and fires a spurious
        # "results incomplete" finding (seen live on a cybersecify.com passive run).
        from apps.core.findings.models import Finding
        from apps.core.workflows.models import Workflow
        full = Workflow.objects.create(name="Full Scan X")
        passive = Workflow.objects.create(name="Passive Scan X")
        _session(status="completed", total_findings=50, workflow=full)
        cur = _session(total_findings=0, workflow=passive, endpoints_probed=0)
        _check_coverage_regression(cur)
        assert not Finding.objects.filter(session=cur, check_type="coverage_regression").exists()

    def test_same_workflow_still_flags(self):
        # Same-workflow drop must still fire (the real signal isn't lost).
        from apps.core.findings.models import Finding
        from apps.core.workflows.models import Workflow
        full = Workflow.objects.create(name="Full Scan Y")
        _session(status="completed", total_findings=50, workflow=full)
        cur = _session(total_findings=5, workflow=full)
        _check_coverage_regression(cur)
        assert Finding.objects.filter(session=cur, check_type="coverage_regression").exists()


@pytest.mark.django_db
class TestCoverageRegressionReport:
    """End-to-end: the coverage-regression Finding must surface in the rendered
    report AND must never be flagged as a 'new finding' delta (it is created after
    delta detection by design)."""

    def _render_html(self, session):
        from unittest.mock import patch
        from django.contrib.auth.models import User
        from django.test import Client

        user = User.objects.create_user("covrepuser", password="x")
        client = Client()
        client.force_login(user)

        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.reports.views._render_pdf", side_effect=capture_html):
            res = client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        return captured["html"]

    def test_regression_finding_renders_and_is_not_a_new_delta(self):
        from django.utils import timezone
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.findings.models import Finding
        from apps.core.workflows.models import Workflow, WorkflowRun
        from apps.core.scans.pipeline import _finalize_session

        # A prior completed scan makes delta detection meaningful (real baseline).
        ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            end_time=timezone.now(),
        )
        cur = _session(status="running", endpoints_probed=10, endpoints_blocked=10)
        # A normal finding unique to `cur` guarantees at least one genuine "new"
        # delta, so the "coverage_regression is not a new delta" check below isn't
        # vacuously true.
        Finding.objects.create(
            session=cur, source="web_checker", target="example.com",
            check_type="missing_header", severity="medium",
            title="Missing security header", description="desc", remediation="fix",
        )
        wf = Workflow.objects.create(name="wf")
        WorkflowRun.objects.create(workflow=wf, session=cur, status="completed")

        _finalize_session(cur)

        # 1. The synthetic coverage-regression finding was created.
        reg = Finding.objects.get(session=cur, check_type="coverage_regression")
        assert reg.title == "Scan coverage dropped sharply — results may be incomplete"

        # 2. Its title renders in the report HTML.
        cur.refresh_from_db()
        html = self._render_html(cur)
        assert "Scan coverage dropped sharply" in html

        # 3. Deltas ran (the normal finding is a 'new' delta) but the synthetic
        #    coverage-regression finding is NOT a 'new' delta — _check_coverage_
        #    regression runs after _detect_deltas by design.
        new_deltas = ScanDelta.objects.filter(session=cur, change_type="new")
        assert new_deltas.count() >= 1
        assert not new_deltas.filter(
            item_identifier__startswith="scan_coverage:coverage_regression"
        ).exists()


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
