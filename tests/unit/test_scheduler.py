"""
Unit tests for apps/core/scheduler/scheduler.py

Tests reap_stuck_scans, purge_expired_blacklisted_tokens, and daily_scan.
"""

import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from apps.core.scheduler.scheduler import (
    SCAN_TIMEOUT_MINUTES,
    purge_expired_blacklisted_tokens,
    reap_stuck_scans,
)


# ---------------------------------------------------------------------------
# reap_stuck_scans
# ---------------------------------------------------------------------------

class TestReapStuckScans:
    def _make_session(self, status, age_minutes, domain="example.com"):
        from apps.core.scans.models import ScanSession
        session = ScanSession.objects.create(
            domain=domain, scan_type="full", status=status,
        )
        # Backdate start_time
        ScanSession.objects.filter(pk=session.pk).update(
            start_time=timezone.now() - timedelta(minutes=age_minutes)
        )
        session.refresh_from_db()
        return session

    def test_reaps_running_scan_past_timeout(self, db):
        session = self._make_session("running", SCAN_TIMEOUT_MINUTES + 1)
        count = reap_stuck_scans()
        assert count == 1
        session.refresh_from_db()
        assert session.status == "failed"
        assert session.end_time is not None

    def test_reaps_pending_scan_past_timeout(self, db):
        session = self._make_session("pending", SCAN_TIMEOUT_MINUTES + 1)
        count = reap_stuck_scans()
        assert count == 1
        session.refresh_from_db()
        assert session.status == "failed"

    def test_does_not_reap_recent_running_scan(self, db):
        session = self._make_session("running", SCAN_TIMEOUT_MINUTES - 1)
        count = reap_stuck_scans()
        assert count == 0
        session.refresh_from_db()
        assert session.status == "running"

    def test_does_not_reap_completed_scan(self, db):
        session = self._make_session("completed", SCAN_TIMEOUT_MINUTES + 10)
        count = reap_stuck_scans()
        assert count == 0
        session.refresh_from_db()
        assert session.status == "completed"

    def test_does_not_reap_cancelled_scan(self, db):
        session = self._make_session("cancelled", SCAN_TIMEOUT_MINUTES + 10)
        count = reap_stuck_scans()
        assert count == 0

    def test_reaps_multiple_stuck_scans(self, db):
        self._make_session("running", SCAN_TIMEOUT_MINUTES + 5, "a.com")
        self._make_session("pending", SCAN_TIMEOUT_MINUTES + 5, "b.com")
        self._make_session("running", SCAN_TIMEOUT_MINUTES - 1, "c.com")  # recent — skip
        count = reap_stuck_scans()
        assert count == 2

    def test_returns_zero_when_nothing_stuck(self, db):
        assert reap_stuck_scans() == 0


# ---------------------------------------------------------------------------
# purge_expired_blacklisted_tokens
# ---------------------------------------------------------------------------

class TestPurgeExpiredBlacklistedTokens:
    def _make_outstanding_token(self, expired=False):
        import uuid as _uuid
        from ninja_jwt.token_blacklist.models import OutstandingToken
        delta = timedelta(seconds=1) if expired else timedelta(days=7)
        sign = -1 if expired else 1
        return OutstandingToken.objects.create(
            jti=str(_uuid.uuid4()),
            token="dummy.token.value",
            expires_at=timezone.now() + sign * delta,
        )

    def test_deletes_expired_tokens(self, db):
        from ninja_jwt.token_blacklist.models import OutstandingToken
        expired = self._make_outstanding_token(expired=True)
        jti = expired.jti
        count = purge_expired_blacklisted_tokens()
        assert count >= 1
        assert not OutstandingToken.objects.filter(jti=jti).exists()

    def test_keeps_valid_tokens(self, db):
        from ninja_jwt.token_blacklist.models import OutstandingToken
        valid = self._make_outstanding_token(expired=False)
        count = purge_expired_blacklisted_tokens()
        assert count == 0
        assert OutstandingToken.objects.filter(jti=valid.jti).exists()

    def test_mixed_expired_and_valid(self, db):
        from ninja_jwt.token_blacklist.models import OutstandingToken
        self._make_outstanding_token(expired=True)
        self._make_outstanding_token(expired=True)
        valid = self._make_outstanding_token(expired=False)
        count = purge_expired_blacklisted_tokens()
        assert count >= 2
        assert OutstandingToken.objects.filter(jti=valid.jti).exists()
        assert OutstandingToken.objects.count() == 1

    def test_returns_zero_when_nothing_to_purge(self, db):
        assert purge_expired_blacklisted_tokens() == 0


# ---------------------------------------------------------------------------
# daily_scan
# ---------------------------------------------------------------------------

class TestDailyScan:
    def test_launches_scan_for_each_active_domain(self, db):
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession
        from apps.core.scheduler.scheduler import daily_scan

        Domain.objects.create(name="a.example.com", is_active=True)
        Domain.objects.create(name="b.example.com", is_active=True)

        with patch("apps.core.scans.tasks.run_scan_task") as mock_task, \
             patch("apps.core.scans.pipeline.create_scan_session") as mock_create:
            fake_session = MagicMock()
            fake_session.id = 1
            fake_session.uuid = uuid.uuid4()
            mock_create.return_value = fake_session

            daily_scan()

        assert mock_create.call_count == 2
        assert mock_task.call_count == 2

    def test_skips_inactive_domains(self, db):
        from apps.core.domains.models import Domain
        from apps.core.scheduler.scheduler import daily_scan

        Domain.objects.create(name="active.example.com", is_active=True)
        Domain.objects.create(name="inactive.example.com", is_active=False)

        with patch("apps.core.scans.tasks.run_scan_task"), \
             patch("apps.core.scans.pipeline.create_scan_session") as mock_create:
            fake_session = MagicMock()
            fake_session.id = 1
            mock_create.return_value = fake_session
            daily_scan()

        assert mock_create.call_count == 1
        call_domain = mock_create.call_args[0][0]
        assert call_domain == "active.example.com"

    def test_skips_domain_when_scan_already_active(self, db):
        from apps.core.domains.models import Domain
        from apps.core.scheduler.scheduler import daily_scan

        Domain.objects.create(name="busy.example.com", is_active=True)

        with patch("apps.core.scans.tasks.run_scan_task") as mock_task, \
             patch("apps.core.scans.pipeline.create_scan_session", return_value=None):
            daily_scan()

        mock_task.assert_not_called()

    def test_no_active_domains_does_nothing(self, db):
        from apps.core.scheduler.scheduler import daily_scan

        with patch("apps.core.scans.tasks.run_scan_task") as mock_task, \
             patch("apps.core.scans.pipeline.create_scan_session") as mock_create:
            daily_scan()

        mock_create.assert_not_called()
        mock_task.assert_not_called()
