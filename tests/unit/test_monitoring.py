"""Unit tests for continuous monitoring on the DBOS branch.

Per-domain Django-Q Schedule rows are gone; monitoring is now the DBOS
`scheduled_monitoring_sweep` workflow calling `run_due_monitoring_scans()`,
which computes due-ness from scan history. `sync_domain_monitoring_jobs` and
`setup_core_schedules` are retained as no-ops for legacy callers.
"""

from datetime import timedelta

import pytest
from unittest.mock import patch


def _make_domain(name, is_active=True, interval=None, authorized=True):
    from django.utils import timezone
    from apps.core.domains.models import Domain, DomainAuthorization
    domain = Domain.objects.create(
        name=name, is_active=is_active, monitoring_interval_hours=interval,
    )
    if authorized:
        DomainAuthorization.objects.create(
            domain=domain, auth_type="owner",
            authorized_at=timezone.now(), authorized_by="test",
        )
    return domain


def _last_scan(domain_name, hours_ago):
    """Give a domain a most-recent scan `hours_ago` hours in the past."""
    from django.utils import timezone
    from apps.core.scans.models import ScanSession
    s = ScanSession.objects.create(domain=domain_name, scan_type="full", status="completed")
    ScanSession.objects.filter(id=s.id).update(
        start_time=timezone.now() - timedelta(hours=hours_ago)
    )


@pytest.mark.django_db
class TestRunDueMonitoringScans:
    """The monitoring sweep — which domains it scans and which it skips."""

    def _sweep(self):
        from apps.core.scheduler.scheduler import run_due_monitoring_scans
        fired = []
        with patch("apps.core.scheduler.scheduler.run_monitoring_scan",
                   side_effect=lambda d: fired.append(d)):
            run_due_monitoring_scans()
        return fired

    def test_never_scanned_domain_is_due(self):
        _make_domain("fresh.com", interval=6)
        assert self._sweep() == ["fresh.com"]

    def test_due_when_last_scan_older_than_interval(self):
        _make_domain("due.com", interval=6)
        _last_scan("due.com", hours_ago=10)
        assert self._sweep() == ["due.com"]

    def test_not_due_when_recently_scanned(self):
        _make_domain("recent.com", interval=6)
        _last_scan("recent.com", hours_ago=1)
        assert self._sweep() == []

    def test_unauthorized_domain_skipped(self):
        _make_domain("unauth.com", interval=6, authorized=False)
        assert self._sweep() == []

    def test_inactive_domain_skipped(self):
        _make_domain("inactive.com", is_active=False, interval=6)
        assert self._sweep() == []

    def test_domain_without_interval_skipped(self):
        _make_domain("nowatch.com", interval=None)
        assert self._sweep() == []

    def test_multiple_domains_only_due_ones_fire(self):
        _make_domain("a.com", interval=6)                     # never scanned -> due
        _make_domain("b.com", interval=6); _last_scan("b.com", 1)   # recent -> not due
        _make_domain("c.com", interval=6); _last_scan("c.com", 12)  # old -> due
        assert sorted(self._sweep()) == ["a.com", "c.com"]


@pytest.mark.django_db
class TestSchedulingIsDBOS:
    """Scheduling moved to DBOS @scheduled workflows; the old Django-Q setup
    helpers are no-ops."""

    def test_setup_core_schedules_is_noop(self):
        from apps.core.scheduler.scheduler import setup_core_schedules
        # Must not raise and must not require django_q.
        setup_core_schedules()

    def test_sync_domain_monitoring_jobs_is_noop(self):
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        _make_domain("watch.com", interval=6)
        sync_domain_monitoring_jobs()  # no schedule rows to create anymore

    def test_scheduled_workflows_register_as_pollers(self):
        from apps.core.durable.dbos_app import configure_dbos
        from dbos._dbos import _get_or_create_dbos_registry

        configure_dbos()
        pollers = getattr(_get_or_create_dbos_registry(), "pollers", [])
        # daily scan, monitoring sweep, user-scan sweep, watchdog, token purge.
        assert len(pollers) >= 5
