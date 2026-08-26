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
        d = Domain.objects.create(name="example.org", is_primary=False)
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
        from apps.core.domains.api import _enrich_domains
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan == completed_session

    def test_never_scanned_domain_has_no_last_scan(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.api import _enrich_domains
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan is None

    def test_last_scan_shows_any_status(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.api import _enrich_domains
        from apps.core.scans.models import ScanSession
        running = ScanSession.objects.create(domain="example.com", status="running")
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan == running

    def test_findings_summary_counts(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.api import _enrich_domains
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
        from apps.core.domains.api import _enrich_domains
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
        from apps.core.domains.api import _enrich_domains
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
        from apps.core.domains.api import _enrich_domains
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
        from apps.core.domains.api import _enrich_domains
        _enrich_domains([])  # must not raise


# ---------------------------------------------------------------------------
# delete_domain — manual cleanup of CharField-linked scan data (no FK cascade)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDeleteDomain:
    def test_delete_removes_sessions_summaries_and_all_assets(self, auth_client):
        """ScanSession.domain is a CharField, not an FK to Domain — so deleting a
        Domain does NOT cascade to its scan data. delete_domain must manually purge
        every session (which cascades to its assets/findings), every ScanSummary,
        and the domain itself, leaving no orphans."""
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL
        from apps.core.findings.models import Finding
        from apps.core.insights.models import ScanSummary
        from django.utils import timezone

        name = "deltest.com"
        domain = Domain.objects.create(name=name)

        # A completed session with the full asset chain + a finding + a delta.
        sess = ScanSession.objects.create(
            domain=name, scan_type="full", status="completed", end_time=timezone.now(),
        )
        sub = Subdomain.objects.create(session=sess, domain=name, subdomain="api." + name, source="subfinder")
        ip = IPAddress.objects.create(session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4", port=443, protocol="tcp", state="open", source="naabu")
        URL.objects.create(session=sess, port=port, subdomain=sub, url="https://api." + name, host="api." + name, port_number=443, source="httpx")
        Finding.objects.create(session=sess, source="web_checker", target=name, check_type="cors", severity="high", title="X", description="X", remediation="X")
        ScanDelta.objects.create(session=sess, change_type="new", change_category="finding", item_identifier="web_checker:cors:X")
        ScanSummary.objects.create(
            session=sess, domain=name, scan_date=sess.end_time,
            critical_count=0, high_count=1, medium_count=0, low_count=0,
            total_findings=1, new_exposures=1, removed_exposures=0, tool_breakdown={},
        )

        res = auth_client.post(f"/api/domains/{domain.pk}/delete/")
        assert res.status_code == 200
        assert res.json() == {"deleted": name}

        # Domain, its sessions, summaries, and all child assets/findings/deltas gone.
        assert not Domain.objects.filter(pk=domain.pk).exists()
        assert not ScanSession.objects.filter(domain=name).exists()
        assert not ScanSummary.objects.filter(domain=name).exists()
        assert not Subdomain.objects.filter(session=sess).exists()
        assert not IPAddress.objects.filter(session=sess).exists()
        assert not Port.objects.filter(session=sess).exists()
        assert not URL.objects.filter(session=sess).exists()
        assert not Finding.objects.filter(session=sess).exists()
        assert not ScanDelta.objects.filter(session=sess).exists()

    def test_delete_blocked_while_scan_active(self, auth_client):
        """A domain with a pending/running scan must not be deletable (409)."""
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession

        name = "busydel.com"
        domain = Domain.objects.create(name=name)
        ScanSession.objects.create(domain=name, scan_type="full", status="running")

        res = auth_client.post(f"/api/domains/{domain.pk}/delete/")
        assert res.status_code == 409
        assert Domain.objects.filter(pk=domain.pk).exists()
