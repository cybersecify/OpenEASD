"""Tests for the H2 metrics exporter + heartbeat + /metrics endpoint."""

from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession

pytestmark = pytest.mark.django_db


def _scan(domain, status="completed", **kw):
    return ScanSession.objects.create(domain=domain, status=status, **kw)


class TestRenderMetrics:
    def test_scans_by_status(self):
        from apps.core.console.observability.metrics import render_metrics
        _scan("a.com", "completed")
        _scan("b.com", "completed")
        _scan("c.com", "failed")
        text = render_metrics()
        assert 'openeasd_scans{status="completed"} 2' in text
        assert 'openeasd_scans{status="failed"} 1' in text
        assert "# TYPE openeasd_scans gauge" in text

    def test_queue_depth_counts_active(self):
        from apps.core.console.observability.metrics import render_metrics
        _scan("a.com", "running")
        _scan("b.com", "pending")
        _scan("c.com", "completed")
        text = render_metrics()
        assert "openeasd_scan_queue_depth 2" in text

    def test_findings_by_severity(self):
        from apps.core.console.observability.metrics import render_metrics
        s = _scan("a.com")
        for sev in ("critical", "high", "high"):
            Finding.objects.create(
                session=s, source="nmap", check_type="cve", severity=sev,
                title="t", description="d", remediation="r", target="t",
            )
        text = render_metrics()
        assert 'openeasd_findings{severity="high"} 2' in text
        assert 'openeasd_findings{severity="critical"} 1' in text
        assert 'openeasd_findings{severity="low"} 0' in text

    def test_journey_and_domains(self):
        from apps.core.console.observability.metrics import render_metrics
        s = _scan("a.com", "completed")
        ScanSession.objects.filter(id=s.id).update(
            start_time=timezone.now() - timedelta(seconds=120),
            end_time=timezone.now(),
        )
        text = render_metrics()
        assert "openeasd_domains 1" in text
        assert "openeasd_scan_last_journey_seconds" in text

    def test_heartbeat_staleness_metric(self):
        from apps.core.console.observability.metrics import render_metrics
        s = _scan("a.com", "running")
        ScanSession.objects.filter(id=s.id).update(last_progress_at=timezone.now())
        text = render_metrics()
        assert "openeasd_seconds_since_last_progress" in text


class TestMetricsEndpoint:
    def test_endpoint_returns_prometheus_text(self, settings):
        settings.METRICS_ENABLED = True
        _scan("a.com", "completed")
        resp = Client().get("/metrics/")
        assert resp.status_code == 200
        assert resp["Content-Type"].startswith("text/plain")
        assert resp["Cache-Control"] == "no-store"
        assert b"openeasd_scans" in resp.content

    def test_endpoint_unauthenticated(self, settings):
        # No Authorization header → still 200 (like /health).
        settings.METRICS_ENABLED = True
        assert Client().get("/metrics/").status_code == 200

    def test_endpoint_disabled_returns_404(self, settings):
        settings.METRICS_ENABLED = False
        assert Client().get("/metrics/").status_code == 404


class TestHeartbeat:
    def test_step_stamps_last_progress_at(self, transactional_db):
        from apps.core.engine.workflows.models import Workflow, WorkflowRun
        from apps.core.engine.workflows.runner import _run_single_step

        s = ScanSession.objects.create(domain="hb.com", status="running")
        assert s.last_progress_at is None
        wf = Workflow.objects.create(name="HB")
        run = WorkflowRun.objects.create(workflow=wf, session=s)

        from unittest.mock import patch
        with patch("apps.core.engine.workflows.runner._get_runner",
                   return_value=lambda session: []):
            _run_single_step(run, s, "subfinder", order=1)

        s.refresh_from_db()
        assert s.last_progress_at is not None
