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
        from apps.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding
        from apps.insights.models import ScanSummary
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
        from apps.insights.models import ScanSummary
        from django.utils import timezone

        # domain_finding has severity=high
        ScanSummary.objects.create(
            session=completed_session, domain="example.com",
            scan_date=timezone.now(), high_count=1, total_findings=1
        )

        resp = auth_client.get(reverse("dashboard"))
        assert b"No MX records found" in resp.content


@pytest.mark.django_db
class TestHealthCheck:
    def test_health_check_authenticated(self, auth_client):
        resp = auth_client.get(reverse("health"))
        assert resp.status_code == 200
        assert b"OpenEASD" in resp.content

    def test_health_check_requires_login(self, client):
        resp = client.get(reverse("health"))
        assert resp.status_code == 302
