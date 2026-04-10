"""Unit tests for apps/scans — model, tasks, and views."""

import uuid
import datetime
import pytest
from unittest.mock import patch, MagicMock
from django.urls import reverse


# ---------------------------------------------------------------------------
# Task / concurrency tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCreateScanSession:
    def test_creates_session_when_no_active_scan(self, db):
        from apps.core.scans.tasks import create_scan_session
        session = create_scan_session("newdomain.com")
        assert session is not None
        assert session.domain == "newdomain.com"
        assert session.status == "pending"

    def test_returns_none_when_scan_already_pending(self, db):
        from apps.core.scans.tasks import create_scan_session
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="busy.com", scan_type="full", status="pending")
        result = create_scan_session("busy.com")
        assert result is None

    def test_returns_none_when_scan_already_running(self, db):
        from apps.core.scans.tasks import create_scan_session
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="running.com", scan_type="full", status="running")
        result = create_scan_session("running.com")
        assert result is None

    def test_returns_none_on_database_error_when_scan_active(self, db):
        """DatabaseError + active scan → returns None without raising."""
        from apps.core.scans.tasks import create_scan_session
        from apps.core.scans.models import ScanSession
        from django.db import DatabaseError
        ScanSession.objects.create(domain="locktest.com", scan_type="full", status="running")
        with patch("apps.core.scans.tasks.ScanSession.objects.select_for_update", side_effect=DatabaseError("lock")):
            result = create_scan_session("locktest.com")
        assert result is None

    def test_retries_and_creates_session_on_transient_lock(self, db):
        """Transient DatabaseError with no active scan → fallback retry creates session."""
        from apps.core.scans.tasks import create_scan_session
        from django.db import DatabaseError

        call_count = {"n": 0}
        original = __import__("apps.core.scans.models", fromlist=["ScanSession"]).ScanSession.objects.select_for_update

        def patched_select_for_update(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise DatabaseError("transient lock")
            return original(*args, **kwargs)

        with patch("apps.core.scans.tasks.ScanSession.objects.select_for_update", side_effect=patched_select_for_update):
            result = create_scan_session("retrytest.com")
        assert result is not None
        assert result.domain == "retrytest.com"

    def test_triggered_by_stored_correctly(self, db):
        from apps.core.scans.tasks import create_scan_session
        session = create_scan_session("trigger.com", triggered_by="recurring")
        assert session.triggered_by == "recurring"

    def test_completed_scan_allows_new_session(self, db):
        from apps.core.scans.tasks import create_scan_session
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
        job = self._make_job("once_example.com_202504101200")
        result = _parse_job(job)
        assert result["domain"] == "example.com"
        assert result["job_type"] == "one-time"

    def test_once_underscored_domain(self):
        from apps.core.scans.views import _parse_job
        job = self._make_job("once_sub_domain.com_202504101200")
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
        from apps.domain_security.models import DomainFinding
        from apps.core.scans.tasks import _detect_deltas
        from django.utils import timezone

        s1 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="completed", end_time=timezone.now())
        s2 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="completed", end_time=timezone.now())
        DomainFinding.objects.create(session=s1, domain="delta.com", check_type="dns", severity="high", title="Old Issue")
        DomainFinding.objects.create(session=s2, domain="delta.com", check_type="dns", severity="high", title="Old Issue")
        DomainFinding.objects.create(session=s2, domain="delta.com", check_type="dns", severity="medium", title="New Issue")

        _detect_deltas(s2)

        new_deltas = ScanDelta.objects.filter(session=s2, change_type="new")
        assert new_deltas.count() == 1
        assert new_deltas.first().item_identifier == "dns:New Issue"

    def test_removed_findings_create_removed_deltas(self, db):
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.domain_security.models import DomainFinding
        from apps.core.scans.tasks import _detect_deltas
        from django.utils import timezone

        s1 = ScanSession.objects.create(domain="rem.com", scan_type="full", status="completed", end_time=timezone.now())
        s2 = ScanSession.objects.create(domain="rem.com", scan_type="full", status="completed", end_time=timezone.now())
        DomainFinding.objects.create(session=s1, domain="rem.com", check_type="dns", severity="high", title="Gone")
        # s2 has no findings

        _detect_deltas(s2)

        removed = ScanDelta.objects.filter(session=s2, change_type="removed")
        assert removed.count() == 1

    def test_no_previous_session_skips_delta(self, db):
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.scans.tasks import _detect_deltas
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
# View tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanViews:
    def test_scan_list_requires_login(self, client):
        resp = client.get(reverse("scan-list"))
        assert resp.status_code == 302

    def test_scan_list_authenticated(self, auth_client, completed_session):
        resp = auth_client.get(reverse("scan-list"))
        assert resp.status_code == 200

    def test_scan_detail_uses_uuid(self, auth_client, completed_session):
        url = reverse("scan-detail", args=[completed_session.uuid])
        resp = auth_client.get(url)
        assert resp.status_code == 200

    def test_scan_detail_invalid_uuid_returns_404(self, auth_client):
        url = reverse("scan-detail", args=[uuid.uuid4()])
        resp = auth_client.get(url)
        assert resp.status_code == 404

    def test_scan_start_get(self, auth_client):
        resp = auth_client.get(reverse("scan-start"))
        assert resp.status_code == 200
        assert b"Start Scan" in resp.content

    def test_scan_start_prefills_domain(self, auth_client):
        resp = auth_client.get(reverse("scan-start") + "?domain=test.com")
        assert b"test.com" in resp.content

    def test_scan_list_filter_by_domain(self, auth_client, completed_session):
        resp = auth_client.get(reverse("scan-list") + "?domain=example")
        assert resp.status_code == 200
        assert b"example.com" in resp.content

    def test_scan_list_filter_no_match(self, auth_client, completed_session):
        resp = auth_client.get(reverse("scan-list") + "?domain=notexist")
        assert resp.status_code == 200
        assert b"example.com" not in resp.content

    def test_finding_list_requires_login(self, client):
        resp = client.get(reverse("finding-list"))
        assert resp.status_code == 302

    def test_finding_list_authenticated(self, auth_client, domain_finding):
        resp = auth_client.get(reverse("finding-list"))
        assert resp.status_code == 200
        assert b"No MX records found" in resp.content

    def test_finding_list_filter_by_severity(self, auth_client, domain_finding):
        resp = auth_client.get(reverse("finding-list") + "?severity=high")
        assert resp.status_code == 200
        assert b"No MX records found" in resp.content

        resp = auth_client.get(reverse("finding-list") + "?severity=critical")
        assert resp.status_code == 200
        assert b"No MX records found" not in resp.content

    def test_finding_list_invalid_session_id_does_not_crash(self, auth_client):
        """Non-integer session_id must be silently ignored, not raise ValueError."""
        resp = auth_client.get(reverse("finding-list") + "?session_id=not-a-number")
        assert resp.status_code == 200

    def test_finding_list_only_latest_scan_per_domain(self, auth_client, db):
        """Findings from old scans must not appear — only from the latest per domain."""
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding
        from django.utils import timezone

        old_session = ScanSession.objects.create(
            domain="multi.com", scan_type="full", status="completed", end_time=timezone.now()
        )
        new_session = ScanSession.objects.create(
            domain="multi.com", scan_type="full", status="completed", end_time=timezone.now()
        )
        DomainFinding.objects.create(
            session=old_session, domain="multi.com",
            check_type="dns", severity="high", title="Old Finding"
        )
        DomainFinding.objects.create(
            session=new_session, domain="multi.com",
            check_type="dns", severity="medium", title="New Finding"
        )

        resp = auth_client.get(reverse("finding-list"))
        assert b"New Finding" in resp.content
        assert b"Old Finding" not in resp.content


# ---------------------------------------------------------------------------
# Scheduling tests — Run Now / Schedule Once / Recurring
# ---------------------------------------------------------------------------

def _make_mock_job(job_id, next_run_time=None):
    job = MagicMock()
    job.id = job_id
    job.name = job_id
    job.next_run_time = next_run_time
    job.trigger = MagicMock()
    job.trigger.fields = []
    return job


@pytest.mark.django_db
class TestScanStartRunNow:
    """POST schedule_type=now starts scan immediately."""

    def test_run_now_creates_session_and_redirects(self, auth_client):
        from apps.core.scans.models import ScanSession
        with patch("apps.core.scans.views.threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            resp = auth_client.post(reverse("scan-start"), {
                "domain": "runnow.com",
                "schedule_type": "now",
            })
        assert ScanSession.objects.filter(domain="runnow.com", status="pending").exists()
        assert resp.status_code == 302
        session = ScanSession.objects.get(domain="runnow.com")
        assert str(session.uuid) in resp["Location"]

    def test_run_now_already_running_shows_error(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="busy.com", scan_type="full", status="running")
        resp = auth_client.post(reverse("scan-start"), {
            "domain": "busy.com",
            "schedule_type": "now",
        })
        assert resp.status_code == 200
        assert b"already running" in resp.content

    def test_run_now_thread_is_started(self, auth_client):
        with patch("apps.core.scans.views.threading.Thread") as mock_thread:
            instance = MagicMock()
            mock_thread.return_value = instance
            auth_client.post(reverse("scan-start"), {
                "domain": "threadtest.com",
                "schedule_type": "now",
            })
        instance.start.assert_called_once()

    def test_run_now_triggered_by_is_manual(self, auth_client):
        from apps.core.scans.models import ScanSession
        with patch("apps.core.scans.views.threading.Thread"):
            auth_client.post(reverse("scan-start"), {
                "domain": "manualcheck.com",
                "schedule_type": "now",
            })
        session = ScanSession.objects.get(domain="manualcheck.com")
        assert session.triggered_by == "manual"


@pytest.mark.django_db
class TestScanStartScheduleOnce:
    """POST schedule_type=once registers a one-time APScheduler job."""

    def _post_once(self, auth_client, domain="once.com", scheduled_at="2030-12-01 10:00"):
        with patch("apps.core.scans.views._schedule_once") as mock_sched:
            resp = auth_client.post(reverse("scan-start"), {
                "domain": domain,
                "schedule_type": "once",
                "scheduled_at": scheduled_at,
            })
        return resp, mock_sched

    def test_once_calls_schedule_once(self, auth_client):
        resp, mock_sched = self._post_once(auth_client)
        mock_sched.assert_called_once()
        args = mock_sched.call_args[0]
        assert args[0] == "once.com"

    def test_once_redirects_after_scheduling(self, auth_client):
        resp, _ = self._post_once(auth_client)
        assert resp.status_code == 302

    def test_once_does_not_create_scan_session(self, auth_client):
        from apps.core.scans.models import ScanSession
        self._post_once(auth_client, domain="nosession.com")
        assert not ScanSession.objects.filter(domain="nosession.com").exists()

    def test_once_missing_scheduled_at_shows_error(self, auth_client):
        resp = auth_client.post(reverse("scan-start"), {
            "domain": "missing.com",
            "schedule_type": "once",
            "scheduled_at": "",
        })
        assert resp.status_code == 200  # form re-rendered with error


@pytest.mark.django_db
class TestScanStartRecurring:
    """POST schedule_type=recurring registers a recurring APScheduler job."""

    def _post_recurring(self, auth_client, domain="rec.com", recurrence="daily", time="02:00"):
        with patch("apps.core.scans.views._schedule_recurring") as mock_sched:
            resp = auth_client.post(reverse("scan-start"), {
                "domain": domain,
                "schedule_type": "recurring",
                "recurrence": recurrence,
                "recurrence_time": time,
            })
        return resp, mock_sched

    def test_recurring_calls_schedule_recurring(self, auth_client):
        resp, mock_sched = self._post_recurring(auth_client)
        mock_sched.assert_called_once()
        args = mock_sched.call_args[0]
        assert args[0] == "rec.com"
        assert args[1] == "daily"

    def test_recurring_redirects_after_scheduling(self, auth_client):
        resp, _ = self._post_recurring(auth_client)
        assert resp.status_code == 302

    def test_weekly_recurring_passes_correct_recurrence(self, auth_client):
        resp, mock_sched = self._post_recurring(auth_client, recurrence="weekly")
        args = mock_sched.call_args[0]
        assert args[1] == "weekly"

    def test_recurring_does_not_create_scan_session(self, auth_client):
        from apps.core.scans.models import ScanSession
        self._post_recurring(auth_client, domain="nosession2.com")
        assert not ScanSession.objects.filter(domain="nosession2.com").exists()


@pytest.mark.django_db
class TestScheduledJobsView:
    """GET /scans/scheduled/ lists user jobs, hides built-ins."""

    def _mock_scheduler(self, jobs):
        mock_sched = MagicMock()
        mock_sched.get_jobs.return_value = jobs
        return mock_sched

    def test_scheduled_jobs_requires_login(self, client):
        resp = client.get(reverse("scheduled-jobs"))
        assert resp.status_code == 302

    def test_scheduled_jobs_empty(self, auth_client):
        with patch("apps.core.scheduler.get_scheduler", return_value=self._mock_scheduler([])):
            resp = auth_client.get(reverse("scheduled-jobs"))
        assert resp.status_code == 200

    def test_recurring_job_shown(self, auth_client):
        job = _make_mock_job("recurring_example.com")
        with patch("apps.core.scheduler.get_scheduler", return_value=self._mock_scheduler([job])):
            resp = auth_client.get(reverse("scheduled-jobs"))
        assert b"example.com" in resp.content

    def test_builtin_jobs_hidden(self, auth_client):
        jobs = [
            _make_mock_job("daily_scan"),
            _make_mock_job("watchdog_reap_stuck_scans"),
        ]
        with patch("apps.core.scheduler.get_scheduler", return_value=self._mock_scheduler(jobs)):
            resp = auth_client.get(reverse("scheduled-jobs"))
        assert b"daily_scan" not in resp.content
        assert b"watchdog_reap_stuck_scans" not in resp.content

    def test_once_job_shown_as_one_time(self, auth_client):
        job = _make_mock_job("once_example.com_202512011000")
        with patch("apps.core.scheduler.get_scheduler", return_value=self._mock_scheduler([job])):
            resp = auth_client.get(reverse("scheduled-jobs"))
        assert b"example.com" in resp.content


@pytest.mark.django_db
class TestCancelScheduledJob:
    """POST /scans/scheduled/<job_id>/cancel/ removes the job."""

    def test_cancel_recurring_job(self, auth_client):
        mock_sched = MagicMock()
        with patch("apps.core.scheduler.get_scheduler", return_value=mock_sched):
            resp = auth_client.post(reverse("cancel-scheduled-job", args=["recurring_example.com"]))
        mock_sched.remove_job.assert_called_once_with("recurring_example.com")
        assert resp.status_code == 302

    def test_cancel_once_job(self, auth_client):
        mock_sched = MagicMock()
        with patch("apps.core.scheduler.get_scheduler", return_value=mock_sched):
            resp = auth_client.post(reverse("cancel-scheduled-job", args=["once_example.com_202512011000"]))
        mock_sched.remove_job.assert_called_once()
        assert resp.status_code == 302

    def test_cancel_builtin_job_blocked(self, auth_client):
        mock_sched = MagicMock()
        with patch("apps.core.scheduler.get_scheduler", return_value=mock_sched):
            auth_client.post(reverse("cancel-scheduled-job", args=["daily_scan"]))
        mock_sched.remove_job.assert_not_called()

    def test_cancel_already_gone_job_does_not_crash(self, auth_client):
        from apscheduler.jobstores.base import JobLookupError
        mock_sched = MagicMock()
        mock_sched.remove_job.side_effect = JobLookupError("recurring_gone.com")
        with patch("apps.core.scheduler.get_scheduler", return_value=mock_sched):
            resp = auth_client.post(reverse("cancel-scheduled-job", args=["recurring_gone.com"]))
        assert resp.status_code == 302  # must not crash
