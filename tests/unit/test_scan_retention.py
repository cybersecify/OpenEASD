"""Tests for scan retention / pruning (H3 — bounded result store).

prune_old_scans is OPT-IN (no-op unless SCAN_RETENTION_ENABLED). When enabled it
keeps, per domain, the newest KEEP_PER_DOMAIN scans + any within MAX_AGE_DAYS,
always keeps the single newest, never deletes pending/running, and cascades.
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession
from apps.core.engine.scheduler.scheduler import prune_old_scans

pytestmark = pytest.mark.django_db


def _scan(domain, *, status="completed", age_days=0):
    s = ScanSession.objects.create(domain=domain, status=status)
    if age_days:
        # start_time is auto_now_add; override via update to backdate.
        ScanSession.objects.filter(id=s.id).update(
            start_time=timezone.now() - timedelta(days=age_days)
        )
        s.refresh_from_db()
    return s


def test_noop_when_disabled(settings):
    settings.SCAN_RETENTION_ENABLED = False
    for i in range(5):
        _scan("ex.com", age_days=i + 1)
    assert prune_old_scans() == 0
    assert ScanSession.objects.count() == 5


def test_keeps_newest_n_per_domain(settings):
    settings.SCAN_RETENTION_ENABLED = True
    settings.SCAN_RETENTION_KEEP_PER_DOMAIN = 3
    settings.SCAN_RETENTION_MAX_AGE_DAYS = 0  # disable age rule → count only
    # 6 scans, ages 10..60 days so all are outside any age window.
    for d in range(10, 70, 10):
        _scan("ex.com", age_days=d)
    deleted = prune_old_scans()
    assert deleted == 3  # 6 - keep 3
    assert ScanSession.objects.filter(domain="ex.com").count() == 3


def test_max_age_keeps_recent_beyond_n(settings):
    settings.SCAN_RETENTION_ENABLED = True
    settings.SCAN_RETENTION_KEEP_PER_DOMAIN = 2
    settings.SCAN_RETENTION_MAX_AGE_DAYS = 90
    # 4 recent (within 90d) + 2 old (beyond 90d). Keep: newest 2 by count + all
    # within-age → all 4 recent kept; the 2 old ones beyond both windows deleted.
    for d in (5, 20, 40, 80):
        _scan("ex.com", age_days=d)
    for d in (120, 200):
        _scan("ex.com", age_days=d)
    deleted = prune_old_scans()
    assert deleted == 2
    remaining_ages_ok = ScanSession.objects.filter(domain="ex.com").count() == 4
    assert remaining_ages_ok


def test_always_keeps_newest_even_if_old(settings):
    settings.SCAN_RETENTION_ENABLED = True
    settings.SCAN_RETENTION_KEEP_PER_DOMAIN = 0  # count window keeps nothing
    settings.SCAN_RETENTION_MAX_AGE_DAYS = 30
    # single scan, very old → still kept (never leave a domain with zero scans)
    _scan("ex.com", age_days=365)
    deleted = prune_old_scans()
    assert deleted == 0
    assert ScanSession.objects.filter(domain="ex.com").count() == 1


def test_never_deletes_pending_or_running(settings):
    # NB: a partial unique constraint (uniq_active_scan_per_domain) allows at most
    # one active (pending/running) scan per domain, so the running and pending
    # cases use different domains.
    settings.SCAN_RETENTION_ENABLED = True
    settings.SCAN_RETENTION_KEEP_PER_DOMAIN = 1
    settings.SCAN_RETENTION_MAX_AGE_DAYS = 0
    # ex.com: newest terminal kept, old terminal deleted, running never deleted.
    _scan("ex.com", status="completed", age_days=10)  # newest terminal (kept)
    _scan("ex.com", status="completed", age_days=40)  # old terminal → deleted
    _scan("ex.com", status="running", age_days=20)    # in-flight, never deleted
    # ex2.com: a pending (active) scan + one terminal — pending never deleted.
    _scan("ex2.com", status="pending", age_days=5)    # in-flight, never deleted
    _scan("ex2.com", status="completed", age_days=30)  # only terminal → kept (newest)
    deleted = prune_old_scans()
    assert deleted == 1  # only ex.com's old completed scan
    assert ScanSession.objects.filter(domain="ex.com", status="running").exists()
    assert ScanSession.objects.filter(domain="ex2.com", status="pending").exists()


def test_prune_is_per_domain(settings):
    settings.SCAN_RETENTION_ENABLED = True
    settings.SCAN_RETENTION_KEEP_PER_DOMAIN = 1
    settings.SCAN_RETENTION_MAX_AGE_DAYS = 0
    for d in (10, 20, 30):
        _scan("a.com", age_days=d)
    for d in (10, 20):
        _scan("b.com", age_days=d)
    deleted = prune_old_scans()
    assert deleted == 3  # a.com: 3-1=2 ; b.com: 2-1=1
    assert ScanSession.objects.filter(domain="a.com").count() == 1
    assert ScanSession.objects.filter(domain="b.com").count() == 1


def test_cascade_deletes_findings(settings):
    settings.SCAN_RETENTION_ENABLED = True
    settings.SCAN_RETENTION_KEEP_PER_DOMAIN = 1
    settings.SCAN_RETENTION_MAX_AGE_DAYS = 0
    newest = _scan("ex.com", age_days=5)
    old = _scan("ex.com", age_days=50)
    Finding.objects.create(
        session=old, source="nmap", check_type="cve", severity="high",
        title="old", description="d", remediation="r", target="t",
    )
    Finding.objects.create(
        session=newest, source="nmap", check_type="cve", severity="high",
        title="new", description="d", remediation="r", target="t",
    )
    prune_old_scans()
    assert not ScanSession.objects.filter(id=old.id).exists()
    assert Finding.objects.filter(session_id=old.id).count() == 0  # cascaded
    assert Finding.objects.filter(session_id=newest.id).count() == 1
