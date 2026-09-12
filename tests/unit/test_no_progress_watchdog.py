"""Tests for the H10 no-progress watchdog (reap_stuck_scans heartbeat path).

A running scan is reaped when its last_progress_at heartbeat is stale beyond
SCAN_NO_PROGRESS_MINUTES, while a slow-but-heartbeating scan is left alone. The
24h hard cap (SCAN_TIMEOUT_MINUTES) still applies to a heartbeating-but-overlong
run.
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.core.engine.scans.models import ScanSession
from apps.core.engine.scheduler.scheduler import reap_stuck_scans

pytestmark = pytest.mark.django_db


def _running(domain, *, started_min_ago, progress_min_ago=None):
    s = ScanSession.objects.create(domain=domain, status="running")
    fields = {"start_time": timezone.now() - timedelta(minutes=started_min_ago)}
    if progress_min_ago is not None:
        fields["last_progress_at"] = timezone.now() - timedelta(minutes=progress_min_ago)
    ScanSession.objects.filter(id=s.id).update(**fields)
    s.refresh_from_db()
    return s


def test_fresh_heartbeat_not_reaped(settings):
    settings.SCAN_NO_PROGRESS_MINUTES = 60
    settings.SCAN_TIMEOUT_MINUTES = 1440
    # running 90 min but heartbeated 2 min ago → slow-but-alive → NOT reaped.
    s = _running("a.com", started_min_ago=90, progress_min_ago=2)
    reap_stuck_scans()
    s.refresh_from_db()
    assert s.status == "running"


def test_stale_heartbeat_reaped(settings):
    settings.SCAN_NO_PROGRESS_MINUTES = 60
    settings.SCAN_TIMEOUT_MINUTES = 1440
    # heartbeated 90 min ago (> 60) though well under the 24h cap → wedged → reaped.
    s = _running("a.com", started_min_ago=120, progress_min_ago=90)
    reap_stuck_scans()
    s.refresh_from_db()
    assert s.status in ("failed", "partial")


def test_null_heartbeat_reaped_when_old(settings):
    settings.SCAN_NO_PROGRESS_MINUTES = 60
    settings.SCAN_TIMEOUT_MINUTES = 1440
    # never completed a step (NULL heartbeat), started 90 min ago → reaped.
    s = _running("a.com", started_min_ago=90, progress_min_ago=None)
    reap_stuck_scans()
    s.refresh_from_db()
    assert s.status in ("failed", "partial")


def test_null_heartbeat_recent_not_reaped(settings):
    settings.SCAN_NO_PROGRESS_MINUTES = 60
    settings.SCAN_TIMEOUT_MINUTES = 1440
    # just started (5 min), no step finished yet → within grace → NOT reaped.
    s = _running("a.com", started_min_ago=5, progress_min_ago=None)
    reap_stuck_scans()
    s.refresh_from_db()
    assert s.status == "running"


def test_hard_cap_still_reaps_heartbeating_overlong(settings):
    settings.SCAN_NO_PROGRESS_MINUTES = 60
    settings.SCAN_TIMEOUT_MINUTES = 1440  # 24h
    # heartbeating (fresh) but running 25h → exceeds the hard cap → reaped.
    s = _running("a.com", started_min_ago=1500, progress_min_ago=1)
    reap_stuck_scans()
    s.refresh_from_db()
    assert s.status in ("failed", "partial")
