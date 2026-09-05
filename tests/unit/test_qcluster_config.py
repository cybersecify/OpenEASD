"""Scan-timeout invariants (DBOS branch).

The original production bug was config drift in the old Django-Q cluster
(timeout 3600 / retry 7200, no max_attempts) that killed long scans and
re-queued zombies. Django-Q is gone; DBOS is durable and re-runs from
checkpoints, so the requeue-zombie class can't occur. What still matters is
that the stuck-scan watchdog never reaps a scan whose worker is legitimately
still running — locked here against SCAN_TASK_TIMEOUT.
"""

from django.conf import settings

from apps.core.scheduler.scheduler import SCAN_TIMEOUT_MINUTES


def test_django_q_cluster_removed():
    """Q_CLUSTER must be gone — DBOS is the execution layer now."""
    assert not hasattr(settings, "Q_CLUSTER")


def test_scan_task_timeout_defined():
    assert isinstance(settings.SCAN_TASK_TIMEOUT, int)
    assert settings.SCAN_TASK_TIMEOUT > 0


def test_watchdog_at_or_above_worker_timeout():
    """The watchdog (minutes) must be >= the per-scan wall-clock cap (seconds/60),
    or reap_stuck_scans could flip a healthy long scan to 'partial' mid-run."""
    assert SCAN_TIMEOUT_MINUTES >= settings.SCAN_TASK_TIMEOUT / 60
