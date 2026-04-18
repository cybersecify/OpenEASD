"""Unit tests for apps/domains — model and enrichment logic."""

import pytest


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainModel:
    def test_create_primary_domain(self):
        from apps.core.domains.models import Domain
        d = Domain.objects.create(name="cybersecify.com", is_primary=True)
        assert d.is_primary is True
        assert d.is_active is True  # default

    def test_create_related_domain(self):
        from apps.core.domains.models import Domain
        d = Domain.objects.create(name="cybersecify.in", is_primary=False)
        assert d.is_primary is False

    def test_domain_name_unique(self):
        from apps.core.domains.models import Domain
        from django.db import IntegrityError
        Domain.objects.create(name="unique.com")
        with pytest.raises(IntegrityError):
            Domain.objects.create(name="unique.com")

    def test_str_representation(self):
        from apps.core.domains.models import Domain
        d = Domain.objects.create(name="test.com")
        assert "test.com" in str(d)

    def test_toggle_active(self, domain):
        domain.is_active = False
        domain.save()
        domain.refresh_from_db()
        assert domain.is_active is False


# ---------------------------------------------------------------------------
# Enrichment helper tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainListEnrichment:
    def test_last_scan_attached(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan == completed_session

    def test_never_scanned_domain_has_no_last_scan(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan is None

    def test_last_scan_shows_any_status(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.scans.models import ScanSession
        running = ScanSession.objects.create(domain="example.com", status="running")
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan == running

    def test_findings_summary_counts(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="missing_header", severity="critical", status="open",
            title="X", description="X", remediation="X",
        )
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="missing_header", severity="critical", status="open",
            title="X", description="X", remediation="X",
        )
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="cors", severity="high", status="open",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        fs = domains[0].findings_summary
        assert fs.get("critical") == 2
        assert fs.get("high") == 1

    def test_findings_excludes_resolved(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="missing_header", severity="critical", status="resolved",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].findings_summary == {}

    def test_findings_excludes_info(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="banner", severity="info", status="open",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert "info" not in domains[0].findings_summary

    def test_findings_empty_when_no_completed_scan(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        running = ScanSession.objects.create(domain="example.com", status="running")
        Finding.objects.create(
            session=running, source="web_checker", target="example.com",
            check_type="cors", severity="high", status="open",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].findings_summary == {}

    def test_enrich_empty_list(self):
        from apps.core.domains.views import _enrich_domains
        _enrich_domains([])  # must not raise
