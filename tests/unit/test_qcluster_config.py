"""Regression tests for the Django-Q2 scan-timeout invariants.

The original production bug was pure config drift: timeout 3600 / retry 7200 with
no max_attempts, so every full scan that ran past 1h was killed and then a zombie
was re-queued at exactly 2h. These tests lock the three timers into agreement so
the bug cannot silently reappear.
"""

from django.conf import settings

from apps.core.scheduler.scheduler import SCAN_TIMEOUT_MINUTES


def test_retry_strictly_greater_than_timeout():
    """retry <= timeout makes the broker re-run a task while it's still running."""
    q = settings.Q_CLUSTER
    assert q["retry"] > q["timeout"]


def test_max_attempts_disables_requeue():
    """max_attempts:1 is the real 'no retries' switch — a killed scan is dead."""
    assert settings.Q_CLUSTER.get("max_attempts") == 1


def test_watchdog_at_or_above_worker_timeout():
    """The watchdog must not reap a scan whose worker is still legitimately running.

    SCAN_TIMEOUT_MINUTES (minutes) must be >= the worker hard-kill (seconds/60),
    or reap_stuck_scans flips a healthy long scan to 'partial' mid-run.
    """
    timeout_minutes = settings.Q_CLUSTER["timeout"] / 60
    assert SCAN_TIMEOUT_MINUTES >= timeout_minutes


def test_single_writer_worker():
    """SQLite is single-writer — more than one worker races on task pickup."""
    assert settings.Q_CLUSTER["workers"] == 1
