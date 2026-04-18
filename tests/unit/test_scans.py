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
class TestParseJob:
    """Tests _parse_job() domain extraction, especially for domains with underscores."""

    def _make_job(self, job_id):
        from unittest.mock import MagicMock
        job = MagicMock()
        job.id = job_id
        job.next_run_time = None
        job.name = job_id
        return job

    def test_recurring_plain_domain(self):
        from apps.core.scans.views import _parse_job
        job = self._make_job("recurring_example.com")
        result = _parse_job(job)
        assert result["domain"] == "example.com"
        assert result["job_type"] == "recurring"

    def test_recurring_underscored_domain(self):
        from apps.core.scans.views import _parse_job
        job = self._make_job("recurring_sub_domain.example.com")
        result = _parse_job(job)
        assert result["domain"] == "sub_domain.example.com"

    def test_once_plain_domain(self):
        from apps.core.scans.views import _parse_job
        job = self._make_job("once_example.com_" + "a" * 32)
        result = _parse_job(job)
        assert result["domain"] == "example.com"
        assert result["job_type"] == "one-time"

    def test_once_underscored_domain(self):
        from apps.core.scans.views import _parse_job
        job = self._make_job("once_sub_domain.com_" + "b" * 32)
        result = _parse_job(job)
        assert result["domain"] == "sub_domain.com"

    def test_builtin_jobs_return_none(self):
        from apps.core.scans.views import _parse_job
        for job_id in ("daily_scan", "watchdog_reap_stuck_scans"):
            job = self._make_job(job_id)
            assert _parse_job(job) is None


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
        from unittest.mock import MagicMock
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
        import datetime
        from unittest.mock import patch
        from django.utils import timezone
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
