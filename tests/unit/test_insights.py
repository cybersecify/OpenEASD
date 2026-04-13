"""Unit tests for apps/insights — builder and views."""

import pytest
from django.urls import reverse
from django.utils import timezone


# ---------------------------------------------------------------------------
# Builder tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestBuildInsights:
    def test_creates_scan_summary(self, completed_session, domain_finding):
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        build_insights(completed_session)

        assert ScanSummary.objects.filter(session=completed_session).exists()

    def test_summary_counts_correct_severities(self, db, completed_session):
        from apps.core.findings.models import Finding
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        Finding.objects.create(session=completed_session, source="domain_security", target="example.com", check_type="dns", severity="critical", title="Critical A")
        Finding.objects.create(session=completed_session, source="domain_security", target="example.com", check_type="email", severity="high", title="High B")
        Finding.objects.create(session=completed_session, source="domain_security", target="example.com", check_type="email", severity="medium", title="Med C")

        build_insights(completed_session)

        summary = ScanSummary.objects.get(session=completed_session)
        assert summary.critical_count == 1
        assert summary.high_count == 1
        assert summary.medium_count == 1
        assert summary.low_count == 0
        assert summary.total_findings == 3

    def test_summary_includes_tool_breakdown(self, completed_session, domain_finding):
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        build_insights(completed_session)

        summary = ScanSummary.objects.get(session=completed_session)
        assert "domain_security" in summary.tool_breakdown
        assert summary.tool_breakdown["domain_security"] == 1

    def test_build_insights_idempotent(self, completed_session, domain_finding):
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        build_insights(completed_session)
        build_insights(completed_session)  # second call should update, not duplicate

        assert ScanSummary.objects.filter(session=completed_session).count() == 1

    def test_delta_counts_stored_in_summary(self, db, completed_session):
        from apps.core.scans.models import ScanDelta
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        ScanDelta.objects.create(session=completed_session, change_type="new",
                                  change_category="domain_finding", item_identifier="dns:issue")
        ScanDelta.objects.create(session=completed_session, change_type="new",
                                  change_category="domain_finding", item_identifier="email:issue")

        build_insights(completed_session)

        summary = ScanSummary.objects.get(session=completed_session)
        assert summary.new_exposures == 2
        assert summary.removed_exposures == 0


@pytest.mark.django_db
class TestRebuildFindingTypeSummaries:
    def test_creates_finding_type_entries(self, db, completed_session):
        from apps.core.findings.models import Finding
        from apps.core.insights.builder import _rebuild_finding_type_summaries
        from apps.core.insights.models import FindingTypeSummary
        from apps.core.domains.models import Domain

        Domain.objects.create(name="example.com", is_primary=True)
        Finding.objects.create(session=completed_session, source="domain_security", target="example.com", check_type="dns", severity="medium", title="DNSSEC not enabled")
        Finding.objects.create(session=completed_session, source="domain_security", target="example.com", check_type="dns", severity="medium", title="DNSSEC not enabled")

        _rebuild_finding_type_summaries()

        ft = FindingTypeSummary.objects.get(title="DNSSEC not enabled")
        assert ft.occurrence_count == 2
        assert ft.check_type == "dns"

    def test_excludes_unregistered_domain_findings(self, db, completed_session):
        from apps.core.findings.models import Finding
        from apps.core.insights.builder import _rebuild_finding_type_summaries
        from apps.core.insights.models import FindingTypeSummary
        from apps.core.domains.models import Domain

        # No Domain registered for "example.com"
        Finding.objects.create(session=completed_session, source="domain_security", target="example.com", check_type="dns", severity="medium", title="DNSSEC not enabled")

        _rebuild_finding_type_summaries()

        assert not FindingTypeSummary.objects.filter(title="DNSSEC not enabled").exists()


# ---------------------------------------------------------------------------
# View tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestInsightsView:
    def test_insights_requires_login(self, client):
        resp = client.get(reverse("insights"))
        assert resp.status_code == 302

    def test_insights_empty_state(self, auth_client, domain):
        resp = auth_client.get(reverse("insights"))
        assert resp.status_code == 200
        assert b"No completed scans yet" in resp.content

    def test_insights_shows_trend_data(self, auth_client, domain, scan_summary):
        resp = auth_client.get(reverse("insights"))
        assert resp.status_code == 200
        assert b"example.com" in resp.content

    def test_insights_shows_section_headers(self, auth_client, domain, scan_summary):
        resp = auth_client.get(reverse("insights"))
        assert b"Security Posture" in resp.content
        assert b"Remediation Progress" in resp.content
        assert b"Where to Focus" in resp.content
        assert b"Asset Coverage" in resp.content

    def test_insights_shows_kpi_cards(self, auth_client, domain, scan_summary):
        resp = auth_client.get(reverse("insights"))
        assert b"Open Critical" in resp.content
        assert b"Open High" in resp.content
        assert b"New This Scan" in resp.content
        assert b"Fixed This Scan" in resp.content

    def test_insights_only_shows_active_domain_data(self, auth_client, db, completed_session):
        """Summaries for unregistered domains must not appear."""
        from apps.core.insights.models import ScanSummary
        # No Domain registered — summary should not appear
        ScanSummary.objects.create(
            session=completed_session,
            domain="ghost.com",
            scan_date=timezone.now(),
            total_findings=5,
        )
        resp = auth_client.get(reverse("insights"))
        assert b"ghost.com" not in resp.content


@pytest.mark.django_db
class TestInsightsKPIContext:
    def _get_context(self, auth_client):
        from django.urls import reverse
        resp = auth_client.get(reverse("insights"))
        assert resp.status_code == 200
        return resp.context

    def test_kpi_open_critical_counts_open_critical_only(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="critical", title="CVE-A", status="open")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="critical", title="CVE-B", status="resolved")
        ctx = self._get_context(auth_client)
        assert ctx["kpi_open_critical"] == 1

    def test_kpi_open_high_counts_open_high_only(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="high", title="High-A", status="open")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="high", title="High-B", status="acknowledged")
        ctx = self._get_context(auth_client)
        assert ctx["kpi_open_high"] == 1

    def test_kpi_new_and_fixed_from_latest_summary(self, auth_client, db, domain, scan_summary):
        # scan_summary fixture: new_exposures=3, removed_exposures=0
        ctx = self._get_context(auth_client)
        assert ctx["kpi_new"] == 3
        assert ctx["kpi_fixed"] == 0

    def test_kpi_zero_when_no_scans(self, auth_client, db):
        ctx = self._get_context(auth_client)
        assert ctx["kpi_open_critical"] == 0
        assert ctx["kpi_open_high"] == 0
        assert ctx["kpi_new"] == 0
        assert ctx["kpi_fixed"] == 0
