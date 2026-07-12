"""Unit tests for continuous monitoring — sync_domain_monitoring_jobs and setup_core_schedules."""

import pytest


@pytest.mark.django_db
class TestSyncDomainMonitoringJobs:
    def _make_domain(self, name, is_active=True, interval=None, authorized=True):
        from django.utils import timezone
        from apps.core.domains.models import Domain, DomainAuthorization
        domain = Domain.objects.create(
            name=name, is_active=is_active, monitoring_interval_hours=interval,
        )
        if authorized:
            DomainAuthorization.objects.create(
                domain=domain, auth_type="owner",
                authorized_at=timezone.now().date(), authorized_by="test",
            )
        return domain

    def test_no_schedule_for_unauthorized_domain(self, db):
        """A monitored, active domain with no authorization gets no schedule."""
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("unauth.com", interval=6, authorized=False)
        sync_domain_monitoring_jobs()
        assert not Schedule.objects.filter(name="monitor_unauth.com").exists()

    def test_creates_schedule_for_active_monitored_domain(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("watch.com", interval=6)
        sync_domain_monitoring_jobs()
        assert Schedule.objects.filter(name="monitor_watch.com").exists()

    def test_schedule_uses_correct_minutes(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("watch24.com", interval=24)
        sync_domain_monitoring_jobs()
        sched = Schedule.objects.get(name="monitor_watch24.com")
        assert sched.minutes == 24 * 60

    def test_no_schedule_for_domain_without_interval(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("nowatch.com", interval=None)
        sync_domain_monitoring_jobs()
        assert not Schedule.objects.filter(name="monitor_nowatch.com").exists()

    def test_no_schedule_for_inactive_domain(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("inactive.com", is_active=False, interval=12)
        sync_domain_monitoring_jobs()
        assert not Schedule.objects.filter(name="monitor_inactive.com").exists()

    def test_stale_schedule_removed_when_domain_deactivated(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        from apps.core.domains.models import Domain

        domain = self._make_domain("stale.com", interval=12)
        sync_domain_monitoring_jobs()
        assert Schedule.objects.filter(name="monitor_stale.com").exists()

        domain.is_active = False
        domain.save()
        sync_domain_monitoring_jobs()
        assert not Schedule.objects.filter(name="monitor_stale.com").exists()

    def test_stale_schedule_removed_when_interval_cleared(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        from apps.core.domains.models import Domain

        domain = self._make_domain("cleared.com", interval=6)
        sync_domain_monitoring_jobs()
        assert Schedule.objects.filter(name="monitor_cleared.com").exists()

        domain.monitoring_interval_hours = None
        domain.save()
        sync_domain_monitoring_jobs()
        assert not Schedule.objects.filter(name="monitor_cleared.com").exists()

    def test_idempotent_multiple_calls(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("idempotent.com", interval=48)
        sync_domain_monitoring_jobs()
        sync_domain_monitoring_jobs()
        assert Schedule.objects.filter(name="monitor_idempotent.com").count() == 1

    def test_multiple_domains_each_get_schedule(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("a.com", interval=6)
        self._make_domain("b.com", interval=12)
        self._make_domain("c.com", interval=24)
        sync_domain_monitoring_jobs()
        assert Schedule.objects.filter(name__startswith="monitor_").count() == 3

    def test_schedule_func_points_to_monitoring_runner(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import sync_domain_monitoring_jobs
        self._make_domain("functest.com", interval=6)
        sync_domain_monitoring_jobs()
        sched = Schedule.objects.get(name="monitor_functest.com")
        assert "run_monitoring_scan" in sched.func


@pytest.mark.django_db
class TestSetupCoreSchedules:
    def test_creates_daily_scan_schedule(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import setup_core_schedules
        setup_core_schedules()
        assert Schedule.objects.filter(name="daily_scan").exists()

    def test_creates_watchdog_schedule(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import setup_core_schedules
        setup_core_schedules()
        assert Schedule.objects.filter(name="watchdog_reap_stuck_scans").exists()

    def test_creates_token_purge_schedule(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import setup_core_schedules
        setup_core_schedules()
        assert Schedule.objects.filter(name="purge_blacklisted_tokens").exists()

    def test_idempotent_on_repeated_calls(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import setup_core_schedules
        setup_core_schedules()
        setup_core_schedules()
        assert Schedule.objects.filter(name="daily_scan").count() == 1
        assert Schedule.objects.filter(name="watchdog_reap_stuck_scans").count() == 1

    def test_daily_scan_is_cron_type(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import setup_core_schedules
        setup_core_schedules()
        sched = Schedule.objects.get(name="daily_scan")
        assert sched.schedule_type == Schedule.CRON

    def test_watchdog_is_minutes_type(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import setup_core_schedules
        setup_core_schedules()
        sched = Schedule.objects.get(name="watchdog_reap_stuck_scans")
        assert sched.schedule_type == Schedule.MINUTES

    def test_all_core_schedules_repeat_indefinitely(self, db):
        from django_q.models import Schedule
        from apps.core.scheduler.scheduler import setup_core_schedules
        setup_core_schedules()
        for name in ("daily_scan", "watchdog_reap_stuck_scans", "purge_blacklisted_tokens"):
            sched = Schedule.objects.get(name=name)
            assert sched.repeats == -1, f"{name} should repeat indefinitely"
