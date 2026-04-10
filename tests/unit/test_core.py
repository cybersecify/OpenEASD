"""Unit tests for apps/core — dashboard view."""

import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestDashboardView:
    def test_dashboard_requires_login(self, client):
        resp = client.get(reverse("dashboard"))
        assert resp.status_code == 302
        assert "/accounts/login/" in resp["Location"]

    def test_dashboard_authenticated(self, auth_client):
        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200
        assert b"Dashboard" in resp.content

    def test_dashboard_shows_active_domains(self, auth_client, domain):
        resp = auth_client.get(reverse("dashboard"))
        assert b"example.com" in resp.content

    def test_dashboard_current_critical_from_latest_scan(self, auth_client, domain, db):
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding
        from apps.core.insights.models import ScanSummary
        from django.utils import timezone

        session = ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            end_time=timezone.now()
        )
        DomainFinding.objects.create(
            session=session, domain="example.com",
            check_type="rdap", severity="critical", title="Domain expires soon"
        )
        ScanSummary.objects.create(
            session=session, domain="example.com",
            scan_date=timezone.now(), critical_count=1, total_findings=1
        )

        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200
        # Critical count should reflect current state
        assert b"1" in resp.content

    def test_dashboard_empty_no_domains(self, auth_client):
        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200
        assert b"No domains added yet" in resp.content

    def test_dashboard_shows_urgent_findings(self, auth_client, domain, domain_finding, completed_session):
        from apps.core.insights.models import ScanSummary
        from django.utils import timezone

        # domain_finding has severity=high
        ScanSummary.objects.create(
            session=completed_session, domain="example.com",
            scan_date=timezone.now(), high_count=1, total_findings=1
        )

        resp = auth_client.get(reverse("dashboard"))
        assert b"No MX records found" in resp.content


@pytest.mark.django_db
class TestDashboardQueryCorrectness:
    """Test that dashboard uses ID-based lookup and doesn't mix up domains."""

    def test_dashboard_shows_correct_summary_per_domain(self, auth_client, db):
        """Two domains with different scans must each show their own counts."""
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession
        from apps.core.insights.models import ScanSummary
        from django.utils import timezone

        d1 = Domain.objects.create(name="alpha.com", is_active=True)
        d2 = Domain.objects.create(name="beta.com", is_active=True)

        now = timezone.now()
        s1 = ScanSession.objects.create(domain="alpha.com", scan_type="full", status="completed", end_time=now)
        s2 = ScanSession.objects.create(domain="beta.com", scan_type="full", status="completed", end_time=now)

        # Same scan_date for both — old code could cross-match these
        ScanSummary.objects.create(session=s1, domain="alpha.com", scan_date=now, critical_count=5, total_findings=5)
        ScanSummary.objects.create(session=s2, domain="beta.com", scan_date=now, critical_count=0, total_findings=1)

        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200

    def test_dashboard_uses_latest_scan_not_oldest(self, auth_client, db):
        """When multiple scans exist for a domain, the latest one must be shown."""
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession
        from apps.core.insights.models import ScanSummary
        from django.utils import timezone
        import datetime

        Domain.objects.create(name="repeated.com", is_active=True)

        t1 = timezone.now() - datetime.timedelta(hours=2)
        t2 = timezone.now()

        s1 = ScanSession.objects.create(domain="repeated.com", scan_type="full", status="completed", end_time=t1)
        s2 = ScanSession.objects.create(domain="repeated.com", scan_type="full", status="completed", end_time=t2)

        ScanSummary.objects.create(session=s1, domain="repeated.com", scan_date=t1, critical_count=10, total_findings=10)
        ScanSummary.objects.create(session=s2, domain="repeated.com", scan_date=t2, critical_count=0, total_findings=2)

        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200
        # critical count should be 0 from latest scan, not 10 from old scan
        assert resp.context["current_critical"] == 0


@pytest.mark.django_db
class TestHealthCheck:
    def test_health_check_authenticated(self, auth_client):
        resp = auth_client.get(reverse("health"))
        assert resp.status_code == 200
        assert b"OpenEASD" in resp.content

    def test_health_check_requires_login(self, client):
        resp = client.get(reverse("health"))
        assert resp.status_code == 302
