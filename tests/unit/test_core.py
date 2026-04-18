"""Unit tests for apps/core — context processors."""

import pytest


@pytest.mark.django_db
class TestSidebarCountsContextProcessor:
    def _call(self):
        from apps.core.dashboard.context_processors import sidebar_counts
        return sidebar_counts(None)  # request is not used

    def test_returns_zero_badge_when_no_findings(self, db):
        result = self._call()
        assert result["sidebar_finding_badge"] == 0

    def test_counts_open_critical_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-2024-0001",
            status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 1

    def test_counts_open_high_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="high", title="CVE-2024-0002",
            status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 1

    def test_badge_sums_critical_and_high(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-A", status="open",
        )
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="high", title="CVE-B", status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 2

    def test_does_not_count_non_open_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-A",
            status="acknowledged",
        )
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-B",
            status="resolved",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 0

    def test_does_not_count_medium_or_low_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="medium", title="Med", status="open",
        )
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="low", title="Low", status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 0

    def test_returns_zero_running_when_no_scans(self, db):
        result = self._call()
        assert result["sidebar_running_count"] == 0

    def test_counts_running_scans(self, db):
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
        result = self._call()
        assert result["sidebar_running_count"] == 1

    def test_does_not_count_non_running_scans(self, db):
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")
        result = self._call()
        assert result["sidebar_running_count"] == 0
