"""Unit tests for apps/scans — model, tasks, and pipeline logic."""

import uuid
import datetime
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Task / concurrency tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCreateScanSession:
    def test_creates_session_when_no_active_scan(self, db):
        from apps.core.scans.pipeline import create_scan_session
        session = create_scan_session("newdomain.com")
        assert session is not None
        assert session.domain == "newdomain.com"
        assert session.status == "pending"

    def test_returns_none_when_scan_already_pending(self, db):
        from apps.core.scans.pipeline import create_scan_session
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="busy.com", scan_type="full", status="pending")
        result = create_scan_session("busy.com")
        assert result is None

    def test_returns_none_when_scan_already_running(self, db):
        from apps.core.scans.pipeline import create_scan_session
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="running.com", scan_type="full", status="running")
        result = create_scan_session("running.com")
        assert result is None

    def test_returns_none_on_database_error_when_scan_active(self, db):
        """DatabaseError + active scan → returns None without raising."""
        from apps.core.scans.pipeline import create_scan_session
        from apps.core.scans.models import ScanSession
        from django.db import DatabaseError
        ScanSession.objects.create(domain="locktest.com", scan_type="full", status="running")
        with patch("apps.core.scans.pipeline.ScanSession.objects.select_for_update", side_effect=DatabaseError("lock")):
            result = create_scan_session("locktest.com")
        assert result is None

    def test_retries_and_creates_session_on_transient_lock(self, db):
        """Transient DatabaseError with no active scan → fallback retry creates session."""
        from apps.core.scans.pipeline import create_scan_session
        from django.db import DatabaseError

        call_count = {"n": 0}
        original = __import__("apps.core.scans.models", fromlist=["ScanSession"]).ScanSession.objects.select_for_update

        def patched_select_for_update(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise DatabaseError("transient lock")
            return original(*args, **kwargs)

        with patch("apps.core.scans.pipeline.ScanSession.objects.select_for_update", side_effect=patched_select_for_update):
            result = create_scan_session("retrytest.com")
        assert result is not None
        assert result.domain == "retrytest.com"

    def test_triggered_by_stored_correctly(self, db):
        from apps.core.scans.pipeline import create_scan_session
        session = create_scan_session("trigger.com", triggered_by="recurring")
        assert session.triggered_by == "recurring"

    def test_completed_scan_allows_new_session(self, db):
        from apps.core.scans.pipeline import create_scan_session
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="done.com", scan_type="full", status="completed")
        result = create_scan_session("done.com")
        assert result is not None


@pytest.mark.django_db
class TestParseSchedule:
    """Tests _parse_schedule() domain extraction, especially for domains with underscores."""

    def _make_schedule(self, name, cron="0 2 * * *"):
        s = MagicMock()
        s.name = name
        s.next_run = None
        s.cron = cron
        return s

    def test_recurring_plain_domain(self):
        from apps.core.scans.api import _parse_schedule
        s = self._make_schedule("recurring_example.com")
        result = _parse_schedule(s)
        assert result["domain"] == "example.com"
        assert result["job_type"] == "recurring"

    def test_recurring_underscored_domain(self):
        from apps.core.scans.api import _parse_schedule
        s = self._make_schedule("recurring_sub_domain.example.com")
        result = _parse_schedule(s)
        assert result["domain"] == "sub_domain.example.com"

    def test_once_plain_domain(self):
        from apps.core.scans.api import _parse_schedule
        s = self._make_schedule("once_example.com_" + "a" * 32)
        result = _parse_schedule(s)
        assert result["domain"] == "example.com"
        assert result["job_type"] == "one-time"

    def test_once_underscored_domain(self):
        from apps.core.scans.api import _parse_schedule
        s = self._make_schedule("once_sub_domain.com_" + "b" * 32)
        result = _parse_schedule(s)
        assert result["domain"] == "sub_domain.com"

    def test_builtin_schedules_return_none(self):
        from apps.core.scans.api import _parse_schedule
        for name in ("daily_scan", "watchdog_reap_stuck_scans", "monitor_example.com"):
            s = self._make_schedule(name)
            assert _parse_schedule(s) is None

    def test_weekly_frequency_from_cron(self):
        from apps.core.scans.api import _parse_schedule
        s = self._make_schedule("recurring_example.com", cron="0 2 * * 1")
        result = _parse_schedule(s)
        assert result["frequency"] == "Weekly (Mondays)"

    def test_daily_frequency_from_cron(self):
        from apps.core.scans.api import _parse_schedule
        s = self._make_schedule("recurring_example.com", cron="0 2 * * *")
        result = _parse_schedule(s)
        assert result["frequency"] == "Daily"


@pytest.mark.django_db
class TestDetectDeltas:
    def test_new_findings_create_new_deltas(self, db):
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.findings.models import Finding
        from apps.core.scans.pipeline import _detect_deltas
        from django.utils import timezone

        s1 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="completed", end_time=timezone.now())
        s2 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="completed", end_time=timezone.now())
        Finding.objects.create(session=s1, source="domain_security", target="delta.com", check_type="dns", severity="high", title="Old Issue")
        Finding.objects.create(session=s2, source="domain_security", target="delta.com", check_type="dns", severity="high", title="Old Issue")
        Finding.objects.create(session=s2, source="domain_security", target="delta.com", check_type="dns", severity="medium", title="New Issue")

        _detect_deltas(s2)

        new_deltas = ScanDelta.objects.filter(session=s2, change_type="new")
        assert new_deltas.count() == 1
        assert new_deltas.first().item_identifier == "domain_security:dns:New Issue"

    def test_removed_findings_create_removed_deltas(self, db):
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.findings.models import Finding
        from apps.core.scans.pipeline import _detect_deltas
        from django.utils import timezone

        s1 = ScanSession.objects.create(domain="rem.com", scan_type="full", status="completed", end_time=timezone.now())
        s2 = ScanSession.objects.create(domain="rem.com", scan_type="full", status="completed", end_time=timezone.now())
        Finding.objects.create(session=s1, source="domain_security", target="rem.com", check_type="dns", severity="high", title="Gone")
        # s2 has no findings

        _detect_deltas(s2)

        removed = ScanDelta.objects.filter(session=s2, change_type="removed")
        assert removed.count() == 1

    def test_no_previous_session_skips_delta(self, db):
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.scans.pipeline import _detect_deltas
        from django.utils import timezone

        s = ScanSession.objects.create(domain="first.com", scan_type="full", status="completed", end_time=timezone.now())
        _detect_deltas(s)
        assert ScanDelta.objects.filter(session=s).count() == 0

    def test_subscan_not_used_as_baseline(self, db):
        """A subscan between two full scans must not become the delta baseline."""
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.findings.models import Finding
        from apps.core.scans.pipeline import _detect_deltas
        from django.utils import timezone

        full1 = ScanSession.objects.create(domain="b.com", scan_type="full", status="completed", end_time=timezone.now())
        Finding.objects.create(session=full1, source="web_checker", target="b.com", check_type="hdr", severity="low", title="Missing HSTS")
        # A subscan (subset of tools) runs later — highest id, but not a valid baseline.
        sub = ScanSession.objects.create(domain="b.com", scan_type="subscan", status="completed", end_time=timezone.now())
        Finding.objects.create(session=sub, source="tls_checker", target="b.com:443", check_type="cipher", severity="medium", title="Weak cipher")
        full2 = ScanSession.objects.create(domain="b.com", scan_type="full", status="completed", end_time=timezone.now())
        Finding.objects.create(session=full2, source="web_checker", target="b.com", check_type="hdr", severity="low", title="Missing HSTS")

        _detect_deltas(full2)

        # Baseline is full1, so the unchanged HSTS finding yields no deltas — the
        # subscan's TLS finding must not appear as a spurious "removed".
        assert ScanDelta.objects.filter(session=full2).count() == 0


@pytest.mark.django_db
class TestFinalizeSubscan:
    def test_finalize_skips_deltas_insights_alerts_for_subscan(self, db):
        from unittest.mock import patch
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import _finalize_session
        from django.utils import timezone

        parent = ScanSession.objects.create(domain="s.com", scan_type="full", status="completed", end_time=timezone.now())
        sub = ScanSession.objects.create(domain="s.com", scan_type="subscan", status="running", parent_session=parent)

        with patch("apps.core.scans.pipeline._detect_deltas") as m_delta, \
             patch("apps.core.insights.builder.build_insights") as m_insights, \
             patch("apps.core.scans.pipeline._dispatch_alerts") as m_alerts:
            _finalize_session(sub)

        sub.refresh_from_db()
        assert sub.status == "completed"
        m_delta.assert_not_called()
        m_insights.assert_not_called()
        m_alerts.assert_not_called()

    def test_finalize_runs_deltas_insights_alerts_for_full_scan(self, db):
        from unittest.mock import patch
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import _finalize_session
        from django.utils import timezone

        s = ScanSession.objects.create(domain="f.com", scan_type="full", status="running", end_time=timezone.now())

        with patch("apps.core.scans.pipeline._detect_deltas") as m_delta, \
             patch("apps.core.insights.builder.build_insights") as m_insights, \
             patch("apps.core.scans.pipeline._dispatch_alerts") as m_alerts:
            _finalize_session(s)

        m_delta.assert_called_once()
        m_insights.assert_called_once()
        m_alerts.assert_called_once()


@pytest.mark.django_db
class TestRunScanPendingGuard:
    def test_cancelled_session_is_not_resurrected(self, db):
        """A stop issued while pending must not be overwritten by the queued task."""
        from unittest.mock import patch
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan

        s = ScanSession.objects.create(domain="c.com", scan_type="full", status="cancelled")
        with patch("apps.core.scans.pipeline._run_via_workflow") as m_run:
            run_scan(s.id)

        s.refresh_from_db()
        assert s.status == "cancelled"
        m_run.assert_not_called()

    def test_failed_session_is_not_resurrected(self, db):
        from unittest.mock import patch
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan

        s = ScanSession.objects.create(domain="d.com", scan_type="full", status="failed")
        with patch("apps.core.scans.pipeline._run_via_workflow") as m_run:
            run_scan(s.id)

        s.refresh_from_db()
        assert s.status == "failed"
        m_run.assert_not_called()

    def test_pending_session_runs(self, db):
        from unittest.mock import patch
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan

        s = ScanSession.objects.create(domain="p.com", scan_type="full", status="pending")
        with patch("apps.core.scans.pipeline._run_via_workflow") as m_run, \
             patch("apps.core.scans.pipeline._seed_apex_into_assets"), \
             patch("apps.core.scans.pipeline._finalize_session"):
            run_scan(s.id)

        m_run.assert_called_once()


@pytest.mark.django_db
class TestLatestSessionIdsExcludesSubscans:
    def test_subscan_excluded_from_latest(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.queries import latest_session_ids
        from django.utils import timezone

        full = ScanSession.objects.create(domain="x.com", scan_type="full", status="completed", end_time=timezone.now())
        # Subscan has the higher id but must not be treated as the domain's latest.
        ScanSession.objects.create(domain="x.com", scan_type="subscan", status="completed", end_time=timezone.now())

        ids = latest_session_ids(["x.com"])
        assert ids == [full.id]


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanSessionModel:
    def test_uuid_generated_on_create(self, scan_session):
        assert scan_session.uuid is not None
        assert isinstance(scan_session.uuid, uuid.UUID)

    def test_uuid_unique_per_session(self, db):
        from apps.core.scans.models import ScanSession
        s1 = ScanSession.objects.create(domain="a.com", scan_type="full")
        s2 = ScanSession.objects.create(domain="b.com", scan_type="full")
        assert s1.uuid != s2.uuid

    def test_default_status_is_pending(self, db):
        from apps.core.scans.models import ScanSession
        s = ScanSession.objects.create(domain="test.com", scan_type="full")
        assert s.status == "pending"

    def test_str_representation(self, scan_session):
        s = str(scan_session)
        assert "example.com" in s


@pytest.mark.django_db
class TestScanDeltaModel:
    def test_create_delta(self, completed_session):
        from apps.core.scans.models import ScanDelta
        delta = ScanDelta.objects.create(
            session=completed_session,
            change_type="new",
            change_category="domain_finding",
            item_identifier="dns:No MX records found",
        )
        assert delta.change_type == "new"
        assert delta.session == completed_session

    def test_delta_cascades_on_session_delete(self, completed_session):
        from apps.core.scans.models import ScanDelta
        ScanDelta.objects.create(
            session=completed_session,
            change_type="new",
            change_category="domain_finding",
            item_identifier="test",
        )
        session_id = completed_session.id
        completed_session.delete()
        assert not ScanDelta.objects.filter(session_id=session_id).exists()


# ---------------------------------------------------------------------------
# Template filter tests
# ---------------------------------------------------------------------------

class TestScanDurationLabel:
    """Unit tests for the scan_duration_label template filter."""

    def _make_scan(self, status, start_offset_seconds=-300, end_offset_seconds=None):
        """Build a mock ScanSession without hitting the DB."""
        from django.utils import timezone
        import datetime
        scan = MagicMock()
        scan.status = status
        scan.start_time = timezone.now() - datetime.timedelta(seconds=abs(start_offset_seconds))
        if end_offset_seconds is not None:
            scan.end_time = scan.start_time + datetime.timedelta(seconds=end_offset_seconds)
        else:
            scan.end_time = None
        return scan

    def test_completed_scan_returns_took(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("completed", end_offset_seconds=492)  # 8m 12s
        result = scan_duration_label(scan)
        assert result == "took 8m 12s"

    def test_failed_scan_returns_after(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("failed", end_offset_seconds=63)  # 1m 03s
        result = scan_duration_label(scan)
        assert result == "after 1m 03s"

    def test_running_scan_returns_running(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        from unittest.mock import patch
        scan = self._make_scan("running", start_offset_seconds=221)  # 3m 41s ago
        fixed_now = scan.start_time + datetime.timedelta(seconds=221)
        with patch("apps.core.scans.templatetags.scan_tags.timezone") as mock_tz:
            mock_tz.now.return_value = fixed_now
            result = scan_duration_label(scan)
        assert result == "running 3m 41s"

    def test_pending_scan_returns_empty(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("pending")
        result = scan_duration_label(scan)
        assert result == ""

    def test_no_end_time_returns_empty(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("completed", end_offset_seconds=None)
        result = scan_duration_label(scan)
        assert result == ""

    def test_sub_minute_duration(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("completed", end_offset_seconds=45)
        result = scan_duration_label(scan)
        assert result == "took 45s"

    def test_negative_delta_returns_zero_duration(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("completed", end_offset_seconds=-5)  # end_time before start_time
        result = scan_duration_label(scan)
        assert result == "took 0s"
