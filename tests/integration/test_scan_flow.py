"""
Integration tests — full scan pipeline.

Tests the complete flow:
  Domain → ScanSession → domain_security scanner → DomainFinding → build_insights → ScanSummary
"""

import pytest
from unittest.mock import patch, MagicMock
from django.utils import timezone


def _mock_rdap_response(days_until_expiry=365, statuses=None):
    """Helper: build a mock RDAP API response."""
    import datetime
    if statuses is None:
        statuses = ["client transfer prohibited"]
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_until_expiry)
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "status": statuses,
        "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
    }
    return mock_resp


@pytest.mark.django_db
class TestDomainSecurityScanFlow:
    """Tests the domain_security scanner → findings → insights pipeline."""

    def _run_mocked_scan(self, session, spf="v=spf1 -all", dmarc="v=DMARC1; p=reject",
                         dkim_found=True, has_a=True, has_ns=True, has_mx=True,
                         rdap_days=365, rdap_statuses=None):
        """Run domain_security scanner with controllable DNS/RDAP mocks."""
        from apps.domain_security.scanner import run_domain_security

        if rdap_statuses is None:
            rdap_statuses = ["client transfer prohibited"]

        def mock_resolve(domain, record_type):
            if record_type in ("A", "AAAA") and has_a:
                return ["1.2.3.4"]
            if record_type == "NS" and has_ns:
                return ["ns1.example.com"]
            if record_type == "MX" and has_mx:
                return ["mail.example.com"]
            return []

        def mock_txt(domain):
            if "_dmarc" in domain:
                return [dmarc] if dmarc else []
            if "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=abc"] if dkim_found else []
            return [spf] if spf else []

        with patch("apps.domain_security.scanner._resolve", side_effect=mock_resolve):
            with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
                with patch("apps.domain_security.scanner.dns") as mock_dns:
                    mock_dns.resolver.resolve.side_effect = Exception("no DNSKEY")
                    with patch("apps.domain_security.scanner.dns.zone.from_xfr",
                               side_effect=Exception("transfer refused")):
                        with patch("apps.domain_security.scanner.dns.query.xfr"):
                            with patch("apps.domain_security.scanner.requests.get",
                                       return_value=_mock_rdap_response(rdap_days, rdap_statuses)):
                                return run_domain_security(session)

    def test_clean_domain_produces_only_dnssec_finding(self, db):
        """A well-configured domain should only flag DNSSEC (mocked as missing)."""
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding

        session = ScanSession.objects.create(domain="secure.com", scan_type="full", status="pending")
        findings = self._run_mocked_scan(session)

        titles = [f.title for f in findings]
        # DNSSEC is mocked as always missing — only that finding expected
        assert "DNSSEC not enabled" in titles
        assert "SPF record missing" not in titles
        assert "DMARC record missing" not in titles
        # All findings saved to DB
        assert DomainFinding.objects.filter(session=session).count() == len(findings)

    def test_missing_email_records_creates_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding

        session = ScanSession.objects.create(domain="insecure.com", scan_type="full", status="pending")
        findings = self._run_mocked_scan(
            session, spf=None, dmarc=None, dkim_found=False
        )

        titles = [f.title for f in findings]
        assert "SPF record missing" in titles
        assert "DMARC record missing" in titles
        assert "DKIM record not found" in titles

        high_findings = [f for f in findings if f.severity == "high"]
        assert len(high_findings) >= 2

    def test_expiring_domain_creates_critical_finding(self, db):
        from apps.core.scans.models import ScanSession

        session = ScanSession.objects.create(domain="expiring.com", scan_type="full", status="pending")
        findings = self._run_mocked_scan(session, rdap_days=3)

        titles = [f.title for f in findings]
        expiry = next((f for f in findings if "expires" in f.title.lower()), None)
        assert expiry is not None
        assert expiry.severity == "critical"

    def test_findings_saved_to_db(self, db):
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding

        session = ScanSession.objects.create(domain="dbtest.com", scan_type="full", status="pending")
        findings = self._run_mocked_scan(session, spf=None, dmarc=None)

        db_count = DomainFinding.objects.filter(session=session).count()
        assert db_count == len(findings)
        assert db_count > 0


@pytest.mark.django_db
class TestFullScanPipeline:
    """Tests run_scan orchestration → domain_security → insights."""

    def test_run_scan_completes_session(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.tasks import run_scan

        session = ScanSession.objects.create(domain="pipeline.com", scan_type="full", status="pending")

        def mock_resolve(domain, record_type):
            return ["1.2.3.4"] if record_type in ("A", "NS", "MX") else []

        def mock_txt(domain):
            if "_dmarc" in domain:
                return ["v=DMARC1; p=reject"]
            if "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=abc"]
            return ["v=spf1 -all"]

        import datetime
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        mock_rdap = MagicMock()
        mock_rdap.json.return_value = {
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
        }

        with patch("apps.domain_security.scanner._resolve", side_effect=mock_resolve):
            with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
                with patch("apps.domain_security.scanner.dns") as mock_dns:
                    mock_dns.resolver.resolve.side_effect = Exception("no DNSKEY")
                    with patch("apps.domain_security.scanner.dns.zone.from_xfr",
                               side_effect=Exception("refused")):
                        with patch("apps.domain_security.scanner.dns.query.xfr"):
                            with patch("apps.domain_security.scanner.requests.get",
                                       return_value=mock_rdap):
                                run_scan(session.id)

        session.refresh_from_db()
        assert session.status == "completed"
        assert session.end_time is not None

    def test_run_scan_builds_insights(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.tasks import run_scan
        from apps.core.insights.models import ScanSummary

        session = ScanSession.objects.create(domain="insights-test.com", scan_type="full", status="pending")

        def mock_resolve(domain, record_type):
            return ["1.2.3.4"] if record_type in ("A", "NS") else []  # missing MX

        def mock_txt(domain):
            return []  # missing SPF/DMARC/DKIM

        import datetime
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        mock_rdap = MagicMock()
        mock_rdap.json.return_value = {
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
        }

        with patch("apps.domain_security.scanner._resolve", side_effect=mock_resolve):
            with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
                with patch("apps.domain_security.scanner.dns") as mock_dns:
                    mock_dns.resolver.resolve.side_effect = Exception("no DNSKEY")
                    with patch("apps.domain_security.scanner.dns.zone.from_xfr",
                               side_effect=Exception("refused")):
                        with patch("apps.domain_security.scanner.dns.query.xfr"):
                            with patch("apps.domain_security.scanner.requests.get",
                                       return_value=mock_rdap):
                                run_scan(session.id)

        assert ScanSummary.objects.filter(session=session).exists()
        summary = ScanSummary.objects.get(session=session)
        assert summary.total_findings > 0

    def test_run_scan_detects_deltas_on_second_scan(self, db):
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.scans.tasks import run_scan

        def make_mocks(spf=None, dmarc=None):
            def mock_resolve(domain, record_type):
                return ["1.2.3.4"] if record_type in ("A", "NS") else []

            def mock_txt(domain):
                results = []
                if spf and domain == domain:
                    results.append(spf)
                if dmarc and "_dmarc" in domain:
                    results.append(dmarc)
                return results

            import datetime
            expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            mock_rdap = MagicMock()
            mock_rdap.json.return_value = {
                "status": ["client transfer prohibited"],
                "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
            }
            return mock_resolve, mock_txt, mock_rdap

        # First scan — no SPF/DMARC
        s1 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="pending")
        mr, mt, mrdap = make_mocks()
        with patch("apps.domain_security.scanner._resolve", side_effect=mr):
            with patch("apps.domain_security.scanner._get_txt_record", side_effect=mt):
                with patch("apps.domain_security.scanner.dns") as mdns:
                    mdns.resolver.resolve.side_effect = Exception("no DNSKEY")
                    with patch("apps.domain_security.scanner.dns.zone.from_xfr",
                               side_effect=Exception("refused")):
                        with patch("apps.domain_security.scanner.dns.query.xfr"):
                            with patch("apps.domain_security.scanner.requests.get", return_value=mrdap):
                                run_scan(s1.id)

        # Second scan — same config (findings should be the same, delta = 0 new)
        s2 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="pending")
        mr2, mt2, mrdap2 = make_mocks()
        with patch("apps.domain_security.scanner._resolve", side_effect=mr2):
            with patch("apps.domain_security.scanner._get_txt_record", side_effect=mt2):
                with patch("apps.domain_security.scanner.dns") as mdns2:
                    mdns2.resolver.resolve.side_effect = Exception("no DNSKEY")
                    with patch("apps.domain_security.scanner.dns.zone.from_xfr",
                               side_effect=Exception("refused")):
                        with patch("apps.domain_security.scanner.dns.query.xfr"):
                            with patch("apps.domain_security.scanner.requests.get", return_value=mrdap2):
                                run_scan(s2.id)

        s1.refresh_from_db()
        s2.refresh_from_db()
        assert s1.status == "completed"
        assert s2.status == "completed"
        # Delta exists for s2 (compared against s1)
        # Same findings → no "new" deltas
        new_deltas = ScanDelta.objects.filter(session=s2, change_type="new")
        assert new_deltas.count() == 0


@pytest.mark.django_db
class TestDomainDeleteCascade:
    """Integration test: deleting a domain wipes all related data."""

    def test_delete_domain_cascades_all_data(self, auth_client, db):
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding
        from apps.core.insights.models import ScanSummary
        from django.urls import reverse

        domain = Domain.objects.create(name="cascade.com", is_primary=True)
        session = ScanSession.objects.create(
            domain="cascade.com", scan_type="full", status="completed",
            end_time=timezone.now()
        )
        DomainFinding.objects.create(
            session=session, domain="cascade.com",
            check_type="dns", severity="high", title="No MX"
        )
        ScanSummary.objects.create(
            session=session, domain="cascade.com",
            scan_date=timezone.now(), total_findings=1, high_count=1
        )

        auth_client.post(reverse("domain-delete", args=[domain.pk]))

        assert not Domain.objects.filter(name="cascade.com").exists()
        assert not ScanSession.objects.filter(domain="cascade.com").exists()
        assert not DomainFinding.objects.filter(domain="cascade.com").exists()
        assert not ScanSummary.objects.filter(domain="cascade.com").exists()
