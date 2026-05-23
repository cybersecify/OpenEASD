"""Unit tests for management commands: run_scan, run_daily_scan, run_weekly_scan, backfill_insights."""

from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.utils import timezone


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestRunScanCommand:
    def test_starts_scan_for_domain(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            total_findings=3,
        )
        with patch("apps.core.scans.management.commands.run_scan.create_scan_session", return_value=sess) as mock_create, \
             patch("apps.core.scans.management.commands.run_scan.run_scan") as mock_run:
            out = StringIO()
            call_command("run_scan", "--domain", "example.com", stdout=out)

        mock_create.assert_called_once_with("example.com", triggered_by="manual")
        mock_run.assert_called_once_with(sess.id)
        output = out.getvalue()
        assert "example.com" in output
        assert str(sess.uuid) in output

    def test_prints_error_when_scan_already_active(self):
        with patch("apps.core.scans.management.commands.run_scan.create_scan_session", return_value=None):
            out = StringIO()
            call_command("run_scan", "--domain", "example.com", stdout=out)
        assert "already active" in out.getvalue()

    def test_prints_final_status(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            total_findings=5,
        )
        with patch("apps.core.scans.management.commands.run_scan.create_scan_session", return_value=sess), \
             patch("apps.core.scans.management.commands.run_scan.run_scan"):
            out = StringIO()
            call_command("run_scan", "--domain", "example.com", stdout=out)
        output = out.getvalue()
        assert "completed" in output
        assert "5" in output


# ---------------------------------------------------------------------------
# run_daily_scan
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestRunDailyScanCommand:
    def test_calls_daily_scan(self):
        with patch("apps.core.scans.management.commands.run_daily_scan.daily_scan") as mock_daily:
            mock_daily.return_value = None
            out = StringIO()
            call_command("run_daily_scan", stdout=out)
        mock_daily.assert_called_once()

    def test_prints_done_on_success(self):
        with patch("apps.core.scans.management.commands.run_daily_scan.daily_scan", return_value=None):
            out = StringIO()
            call_command("run_daily_scan", stdout=out)
        assert "Done" in out.getvalue()


# ---------------------------------------------------------------------------
# run_weekly_scan
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestRunWeeklyScanCommand:
    def test_calls_daily_scan(self):
        with patch("apps.core.scans.management.commands.run_weekly_scan.daily_scan") as mock_scan:
            out = StringIO()
            call_command("run_weekly_scan", stdout=out)
        mock_scan.assert_called_once()

    def test_prints_done_on_success(self):
        with patch("apps.core.scans.management.commands.run_weekly_scan.daily_scan"):
            out = StringIO()
            call_command("run_weekly_scan", stdout=out)
        assert "Done" in out.getvalue()


# ---------------------------------------------------------------------------
# backfill_insights
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestBackfillInsightsCommand:
    def test_backfills_completed_scans_without_summary(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            end_time=timezone.now(), total_findings=0,
        )
        with patch("apps.core.insights.management.commands.backfill_insights.build_insights") as mock_build:
            out = StringIO()
            call_command("backfill_insights", stdout=out)
        mock_build.assert_called_once_with(sess)
        assert "1 scan" in out.getvalue()

    def test_skips_scans_that_already_have_summaries(self):
        from apps.core.scans.models import ScanSession
        from apps.core.insights.models import ScanSummary
        sess = ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            end_time=timezone.now(), total_findings=0,
        )
        ScanSummary.objects.create(
            session=sess, domain=sess.domain,
            scan_date=timezone.now(), total_findings=0,
        )
        with patch("apps.core.insights.management.commands.backfill_insights.build_insights") as mock_build:
            out = StringIO()
            call_command("backfill_insights", stdout=out)
        mock_build.assert_not_called()
        assert "already have summaries" in out.getvalue()

    def test_skips_non_completed_scans(self):
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
        with patch("apps.core.insights.management.commands.backfill_insights.build_insights") as mock_build:
            out = StringIO()
            call_command("backfill_insights", stdout=out)
        mock_build.assert_not_called()

    def test_prints_summary_count(self):
        from apps.core.scans.models import ScanSession
        for i in range(3):
            ScanSession.objects.create(
                domain=f"example{i}.com", scan_type="full", status="completed",
                end_time=timezone.now(), total_findings=0,
            )
        with patch("apps.core.insights.management.commands.backfill_insights.build_insights"):
            out = StringIO()
            call_command("backfill_insights", stdout=out)
        assert "3 scan" in out.getvalue()
