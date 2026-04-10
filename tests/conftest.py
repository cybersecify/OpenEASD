"""Shared fixtures for OpenEASD Django tests."""

import pytest
from django.contrib.auth.models import User
from django.utils import timezone


@pytest.fixture
def user(db):
    return User.objects.create_user(username="testuser", password="testpass123")


@pytest.fixture
def auth_client(client, user):
    client.login(username="testuser", password="testpass123")
    return client


@pytest.fixture
def domain(db):
    from apps.core.domains.models import Domain
    return Domain.objects.create(name="example.com", is_primary=True, is_active=True)


@pytest.fixture
def scan_session(db):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")


@pytest.fixture
def completed_session(db):
    from apps.core.scans.models import ScanSession
    session = ScanSession.objects.create(
        domain="example.com",
        scan_type="full",
        status="completed",
        total_findings=3,
        end_time=timezone.now(),
    )
    return session


@pytest.fixture
def domain_finding(db, completed_session):
    from apps.domain_security.models import DomainFinding
    return DomainFinding.objects.create(
        session=completed_session,
        domain="example.com",
        check_type="dns",
        severity="high",
        title="No MX records found",
        description="Domain has no mail exchange records.",
        remediation="Add MX records.",
    )


@pytest.fixture
def scan_summary(db, completed_session):
    from apps.core.insights.models import ScanSummary
    return ScanSummary.objects.create(
        session=completed_session,
        domain="example.com",
        scan_date=completed_session.end_time,
        critical_count=0,
        high_count=1,
        medium_count=2,
        low_count=0,
        total_findings=3,
        new_exposures=3,
        removed_exposures=0,
        tool_breakdown={"domain_security": 3},
    )
