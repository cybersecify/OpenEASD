"""Unit tests for apps/domains — model and views."""

import pytest
from django.urls import reverse


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
# View tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainViews:
    def test_domain_list_requires_login(self, client):
        resp = client.get(reverse("domain-list"))
        assert resp.status_code == 302
        assert "/accounts/login/" in resp["Location"]

    def test_domain_list_authenticated(self, auth_client, domain):
        resp = auth_client.get(reverse("domain-list"))
        assert resp.status_code == 200
        assert b"example.com" in resp.content

    def test_add_domain_post(self, auth_client):
        from apps.core.domains.models import Domain
        resp = auth_client.post(reverse("domain-list"), {
            "name": "newdomain.com",
            "is_primary": False,
        })
        assert resp.status_code == 302
        assert Domain.objects.filter(name="newdomain.com").exists()

    def test_add_duplicate_domain_shows_error(self, auth_client, domain):
        resp = auth_client.post(reverse("domain-list"), {
            "name": "example.com",
            "is_primary": False,
        })
        assert resp.status_code == 200  # re-renders form with error
        assert b"example.com" in resp.content

    def test_toggle_domain(self, auth_client, domain):
        from apps.core.domains.models import Domain
        assert domain.is_active is True
        auth_client.post(reverse("domain-toggle", args=[domain.pk]))
        domain.refresh_from_db()
        assert domain.is_active is False

    def test_delete_domain_removes_scan_data(self, auth_client, domain, completed_session, domain_finding):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding

        assert ScanSession.objects.filter(domain="example.com").exists()
        assert Finding.objects.filter(source="domain_security", target="example.com").exists()

        auth_client.post(reverse("domain-delete", args=[domain.pk]))

        assert not ScanSession.objects.filter(domain="example.com").exists()
        assert not Finding.objects.filter(source="domain_security", target="example.com").exists()

    def test_delete_domain_removes_domain_record(self, auth_client, domain):
        from apps.core.domains.models import Domain
        auth_client.post(reverse("domain-delete", args=[domain.pk]))
        assert not Domain.objects.filter(pk=domain.pk).exists()

    def test_delete_domain_blocked_when_scan_active(self, auth_client, domain):
        """Cannot delete a domain while a scan is pending or running."""
        from apps.core.scans.models import ScanSession
        from apps.core.domains.models import Domain

        ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
        resp = auth_client.post(reverse("domain-delete", args=[domain.pk]))

        # Domain must still exist
        assert Domain.objects.filter(pk=domain.pk).exists()
        # Returns 200 with error message, not redirect
        assert resp.status_code == 200
        assert b"Cannot delete" in resp.content

    def test_delete_domain_allowed_when_only_completed_scans(self, auth_client, domain, completed_session):
        """Completed scans must not block domain deletion."""
        from apps.core.domains.models import Domain

        resp = auth_client.post(reverse("domain-delete", args=[domain.pk]))
        assert resp.status_code == 302
        assert not Domain.objects.filter(pk=domain.pk).exists()

    def test_delete_domain_removes_scan_summaries(self, auth_client, domain, completed_session, scan_summary):
        from apps.core.insights.models import ScanSummary

        auth_client.post(reverse("domain-delete", args=[domain.pk]))
        assert not ScanSummary.objects.filter(domain="example.com").exists()


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

    def test_last_scan_date_rendered(self, auth_client, domain, completed_session):
        resp = auth_client.get(reverse("domain-list"))
        assert resp.status_code == 200
        # Status sub-text rendered
        assert b"completed" in resp.content

    def test_never_scanned_text_rendered(self, auth_client, domain):
        resp = auth_client.get(reverse("domain-list"))
        assert resp.status_code == 200
        assert b"Never scanned" in resp.content

    def test_findings_badges_rendered(self, auth_client, domain, completed_session):
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="cors", severity="critical", status="open",
            title="X", description="X", remediation="X",
        )
        resp = auth_client.get(reverse("domain-list"))
        assert b"critical" in resp.content

    def test_findings_column_shows_dash_when_clean(self, auth_client, domain, completed_session):
        # Clean domain (no open findings) shows em dash
        resp = auth_client.get(reverse("domain-list"))
        assert "—".encode("utf-8") in resp.content

    def test_confirm_delete_colspan_is_6(self, auth_client, domain):
        resp = auth_client.get(reverse("domain-list"))
        assert b'colspan="6"' in resp.content
