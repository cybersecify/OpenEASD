"""Tests for the H7 ScheduledJob registry + dispatch_scheduled.

A backbone cron runs via dispatch_scheduled(name, fn): it honours the
ScheduledJob.enabled toggle, stamps last_run_at, fails open on a missing row,
and the system jobs are seeded by migration.
"""

import pytest

from apps.core.engine.scans.models import ScheduledJob
from apps.core.engine.scheduler.scheduler import dispatch_scheduled

pytestmark = pytest.mark.django_db


# Use test-only names (the real backbone names are pre-seeded by migration 0017,
# and `name` is unique — creating them again would collide).

def test_enabled_job_runs_and_stamps():
    job = ScheduledJob.objects.create(name="t_enabled", enabled=True)
    calls = []
    dispatch_scheduled("t_enabled", lambda: calls.append(1))
    assert calls == [1]
    job.refresh_from_db()
    assert job.last_run_at is not None


def test_disabled_job_is_skipped():
    ScheduledJob.objects.create(name="t_disabled", enabled=False)
    calls = []
    dispatch_scheduled("t_disabled", lambda: calls.append(1))
    assert calls == []  # disabled → not run


def test_disabled_job_does_not_stamp():
    job = ScheduledJob.objects.create(name="t_nostamp", enabled=False)
    dispatch_scheduled("t_nostamp", lambda: None)
    job.refresh_from_db()
    assert job.last_run_at is None


def test_missing_row_fails_open():
    # No ScheduledJob row for this name → the job still runs (never silently disabled).
    calls = []
    dispatch_scheduled("t_no_such_row", lambda: calls.append(1))
    assert calls == [1]


def test_exception_in_lookup_still_runs(monkeypatch):
    # A DB error during the enabled-check must not block the backbone job.
    calls = []

    class Boom:
        def filter(self, *a, **k):
            raise RuntimeError("db down")

    monkeypatch.setattr(ScheduledJob, "objects", Boom())
    dispatch_scheduled("scan_prune", lambda: calls.append(1))
    assert calls == [1]


class TestSeededJobs:
    def test_all_system_jobs_seeded(self):
        # The data migration (0017) seeds one row per backbone cron.
        names = set(ScheduledJob.objects.values_list("name", flat=True))
        assert {
            "daily_scan", "monitoring_sweep", "user_scans_sweep",
            "watchdog", "token_purge", "scan_prune",
        } <= names

    def test_seeded_jobs_enabled_by_default(self):
        assert ScheduledJob.objects.get(name="daily_scan").enabled is True
        assert ScheduledJob.objects.get(name="watchdog").cron  # has a cron string
