"""Unit tests for apps/domain_security — model and scanner logic."""

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainFindingModel:
    def test_create_finding(self, completed_session):
        from apps.domain_security.models import DomainFinding
        f = DomainFinding.objects.create(
            session=completed_session,
            domain="example.com",
            check_type="email",
            severity="high",
            title="SPF record missing",
            description="No SPF record found.",
            remediation="Add SPF record.",
        )
        assert f.pk is not None
        assert f.check_type == "email"

    def test_extra_json_field(self, completed_session):
        from apps.domain_security.models import DomainFinding
        f = DomainFinding.objects.create(
            session=completed_session,
            domain="example.com",
            check_type="rdap",
            severity="medium",
            title="Transfer lock not enabled",
            extra={"statuses": ["active"]},
        )
        f.refresh_from_db()
        assert f.extra["statuses"] == ["active"]

    def test_finding_cascades_on_session_delete(self, domain_finding, completed_session):
        from apps.domain_security.models import DomainFinding
        session_id = completed_session.id
        completed_session.delete()
        assert not DomainFinding.objects.filter(session_id=session_id).exists()

    def test_findings_filtered_by_severity(self, db, completed_session):
        from apps.domain_security.models import DomainFinding
        DomainFinding.objects.create(session=completed_session, domain="example.com",
                                     check_type="dns", severity="critical", title="Critical issue")
        DomainFinding.objects.create(session=completed_session, domain="example.com",
                                     check_type="dns", severity="low", title="Low issue")
        assert DomainFinding.objects.filter(severity="critical").count() == 1
        assert DomainFinding.objects.filter(severity="low").count() == 1


# ---------------------------------------------------------------------------
# Scanner unit tests (DNS checks — mocked)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDNSChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_missing_a_and_aaaa_creates_high_finding(self, db):
        from apps.domain_security.scanner import _check_dns
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._resolve", return_value=[]):
            findings = _check_dns(session, "example.com")

        titles = [f.title for f in findings]
        assert "No A or AAAA record found" in titles
        a_finding = next(f for f in findings if f.title == "No A or AAAA record found")
        assert a_finding.severity == "high"

    def test_missing_ns_creates_high_finding(self, db):
        from apps.domain_security.scanner import _check_dns
        session = self._make_session(db)

        def mock_resolve(domain, record_type):
            if record_type in ("A", "AAAA"):
                return ["1.2.3.4"]  # has A record
            return []  # missing everything else

        with patch("apps.domain_security.scanner._resolve", side_effect=mock_resolve):
            with patch("apps.domain_security.scanner.dns") as mock_dns:
                mock_dns.resolver.resolve.side_effect = Exception("no DNSKEY")
                findings = _check_dns(session, "example.com")

        titles = [f.title for f in findings]
        assert "No NS records found" in titles

    def test_dnssec_not_enabled_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_dns
        session = self._make_session(db)

        def mock_resolve(domain, record_type):
            return ["mock"] if record_type in ("A", "NS", "MX") else []

        with patch("apps.domain_security.scanner._resolve", side_effect=mock_resolve):
            with patch("apps.domain_security.scanner.dns") as mock_dns:
                mock_dns.resolver.resolve.side_effect = Exception("no DNSKEY")
                findings = _check_dns(session, "example.com")

        titles = [f.title for f in findings]
        assert "DNSSEC not enabled" in titles
        dnssec = next(f for f in findings if f.title == "DNSSEC not enabled")
        assert dnssec.severity == "medium"


# ---------------------------------------------------------------------------
# Scanner unit tests (Email checks — mocked)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestEmailChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_missing_spf_creates_high_finding(self, db):
        from apps.domain_security.scanner import _check_email
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record", return_value=[]):
            findings = _check_email(session, "example.com")

        titles = [f.title for f in findings]
        assert "SPF record missing" in titles
        spf = next(f for f in findings if f.title == "SPF record missing")
        assert spf.severity == "high"

    def test_spf_soft_fail_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_email
        session = self._make_session(db)

        def mock_txt(domain):
            if domain == "example.com":
                return ["v=spf1 include:google.com ~all"]
            return []

        with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
            findings = _check_email(session, "example.com")

        titles = [f.title for f in findings]
        assert "SPF policy is soft fail (~all)" in titles
        spf = next(f for f in findings if "soft fail" in f.title)
        assert spf.severity == "medium"

    def test_spf_plus_all_creates_critical_finding(self, db):
        from apps.domain_security.scanner import _check_email
        session = self._make_session(db)

        def mock_txt(domain):
            if domain == "example.com":
                return ["v=spf1 +all"]
            return []

        with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
            findings = _check_email(session, "example.com")

        titles = [f.title for f in findings]
        assert "SPF policy allows all senders (+all)" in titles
        spf = next(f for f in findings if "+all" in f.title)
        assert spf.severity == "critical"

    def test_missing_dmarc_creates_high_finding(self, db):
        from apps.domain_security.scanner import _check_email
        session = self._make_session(db)

        def mock_txt(domain):
            if domain == "example.com":
                return ["v=spf1 -all"]  # good SPF, no DMARC
            return []

        with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
            findings = _check_email(session, "example.com")

        titles = [f.title for f in findings]
        assert "DMARC record missing" in titles

    def test_dmarc_none_policy_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_email
        session = self._make_session(db)

        def mock_txt(domain):
            if domain == "example.com":
                return ["v=spf1 -all"]
            if "_dmarc" in domain:
                return ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
            return []

        with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
            findings = _check_email(session, "example.com")

        titles = [f.title for f in findings]
        assert "DMARC policy is none (monitoring only)" in titles

    def test_dkim_not_found_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_email
        session = self._make_session(db)

        def mock_txt(domain):
            if domain == "example.com":
                return ["v=spf1 -all"]
            if "_dmarc" in domain:
                return ["v=DMARC1; p=reject"]
            return []  # no DKIM for any selector

        with patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt):
            findings = _check_email(session, "example.com")

        titles = [f.title for f in findings]
        assert "DKIM record not found" in titles


# ---------------------------------------------------------------------------
# Scanner unit tests (RDAP checks — mocked)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestRDAPChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def _mock_rdap(self, statuses, days_until_expiry=365):
        import datetime
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_until_expiry)
        return {
            "status": statuses,
            "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
        }

    def test_rdap_failure_creates_info_finding(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        with patch("apps.domain_security.scanner.requests.get", side_effect=Exception("timeout")):
            with patch("apps.domain_security.scanner.time.sleep"):
                findings = _check_rdap(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "RDAP lookup failed" in findings[0].title

    def test_rdap_retries_then_falls_back_to_iana(self, db):
        from apps.domain_security.scanner import _fetch_rdap
        import datetime

        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        iana_bootstrap = {
            "services": [
                [["com"], ["https://rdap.verisign.com/com/v1/"]]
            ]
        }
        rdap_data = {
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
        }

        call_count = 0

        def side_effect(url, timeout=10):
            nonlocal call_count
            call_count += 1
            mock = MagicMock()
            if "rdap.org" in url:
                raise Exception("rdap.org down")
            if "iana.org" in url:
                mock.json.return_value = iana_bootstrap
                return mock
            # authoritative RDAP server
            mock.json.return_value = rdap_data
            return mock

        with patch("apps.domain_security.scanner.requests.get", side_effect=side_effect):
            with patch("apps.domain_security.scanner.time.sleep"):
                data = _fetch_rdap("example.com")

        assert data["status"] == ["client transfer prohibited"]

    def test_rdap_uses_cached_primary_when_available(self, db):
        from apps.domain_security.scanner import _fetch_rdap
        import datetime

        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        rdap_data = {
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
        }

        mock_resp = MagicMock()
        mock_resp.json.return_value = rdap_data

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp) as mock_get:
            data = _fetch_rdap("example.com")

        # Only one request — rdap.org succeeded on first try
        assert mock_get.call_count == 1
        assert data == rdap_data

    def test_domain_expiry_within_7_days_is_critical(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_rdap(
            statuses=["client transfer prohibited"], days_until_expiry=3
        )

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp):
            findings = _check_rdap(session, "example.com")

        expiry_findings = [f for f in findings if "expires" in f.title.lower()]
        assert len(expiry_findings) == 1
        assert expiry_findings[0].severity == "critical"

    def test_domain_expiry_within_30_days_is_high(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_rdap(
            statuses=["client transfer prohibited"], days_until_expiry=20
        )

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp):
            findings = _check_rdap(session, "example.com")

        expiry_findings = [f for f in findings if "expires" in f.title.lower()]
        assert len(expiry_findings) == 1
        assert expiry_findings[0].severity == "high"

    def test_missing_transfer_lock_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_rdap(statuses=["active"])  # no locks at all

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp):
            findings = _check_rdap(session, "example.com")

        titles = [f.title for f in findings]
        assert "Domain transfer lock not enabled" in titles
        lock = next(f for f in findings if "transfer lock" in f.title)
        assert lock.severity == "medium"

    def test_missing_delete_lock_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        mock_resp = MagicMock()
        # Has transfer lock but not delete lock
        mock_resp.json.return_value = self._mock_rdap(
            statuses=["client transfer prohibited"]
        )

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp):
            findings = _check_rdap(session, "example.com")

        titles = [f.title for f in findings]
        assert "Domain delete lock not enabled" in titles
        lock = next(f for f in findings if "delete lock" in f.title)
        assert lock.severity == "medium"

    def test_missing_update_lock_creates_low_finding(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        mock_resp = MagicMock()
        # Has transfer + delete but not update lock
        mock_resp.json.return_value = self._mock_rdap(
            statuses=["client transfer prohibited", "client delete prohibited"]
        )

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp):
            findings = _check_rdap(session, "example.com")

        titles = [f.title for f in findings]
        assert "Domain update lock not enabled" in titles
        lock = next(f for f in findings if "update lock" in f.title)
        assert lock.severity == "low"

    def test_all_locks_enabled_no_lock_findings(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_rdap(
            statuses=[
                "client transfer prohibited",
                "client delete prohibited",
                "client update prohibited",
            ]
        )

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp):
            findings = _check_rdap(session, "example.com")

        lock_findings = [f for f in findings if "lock" in f.title.lower()]
        assert len(lock_findings) == 0

    def test_inactive_domain_creates_critical_finding(self, db):
        from apps.domain_security.scanner import _check_rdap
        session = self._make_session(db)

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_rdap(
            statuses=["inactive", "client transfer prohibited"]
        )

        with patch("apps.domain_security.scanner.requests.get", return_value=mock_resp):
            findings = _check_rdap(session, "example.com")

        titles = [f.title for f in findings]
        assert "Domain is inactive or pending deletion" in titles


# ---------------------------------------------------------------------------
# CAA checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCAAChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_missing_caa_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_caa
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._resolve", return_value=[]):
            findings = _check_caa(session, "example.com")

        assert len(findings) == 1
        assert findings[0].title == "No CAA records found"
        assert findings[0].severity == "medium"

    def test_valid_caa_no_finding(self, db):
        from apps.domain_security.scanner import _check_caa
        session = self._make_session(db)

        mock_record = MagicMock()
        mock_record.to_text.return_value = '0 issue "letsencrypt.org"'

        with patch("apps.domain_security.scanner._resolve", return_value=[mock_record]):
            findings = _check_caa(session, "example.com")

        assert len(findings) == 0

    def test_blocking_caa_creates_high_finding(self, db):
        from apps.domain_security.scanner import _check_caa
        session = self._make_session(db)

        mock_record = MagicMock()
        mock_record.to_text.return_value = '0 issue ";"'

        with patch("apps.domain_security.scanner._resolve", return_value=[mock_record]):
            findings = _check_caa(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "blocks all certificate issuance" in findings[0].title


# ---------------------------------------------------------------------------
# Wildcard DNS checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestWildcardChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_wildcard_enabled_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_wildcard
        session = self._make_session(db)

        mock_answer = MagicMock()
        mock_answer.address = "1.2.3.4"

        with patch("apps.domain_security.scanner.dns") as mock_dns:
            mock_dns.resolver.resolve.return_value = [mock_answer]
            findings = _check_wildcard(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "Wildcard DNS is enabled" in findings[0].title

    def test_no_wildcard_no_finding(self, db):
        from apps.domain_security.scanner import _check_wildcard
        session = self._make_session(db)

        with patch("apps.domain_security.scanner.dns") as mock_dns:
            mock_dns.resolver.resolve.side_effect = Exception("NXDOMAIN")
            findings = _check_wildcard(session, "example.com")

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Zone Transfer (AXFR) checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestZoneTransferChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def _mock_ns(self, ns_host="ns1.example.com"):
        ns = MagicMock()
        ns.target = MagicMock()
        ns.target.__str__ = lambda s: f"{ns_host}."
        return [ns]

    def test_zone_transfer_allowed_creates_critical_finding(self, db):
        from apps.domain_security.scanner import _check_zone_transfer
        session = self._make_session(db)

        ns_records = self._mock_ns()
        mock_zone = MagicMock()
        mock_zone.nodes = {"node1": None, "node2": None}

        with patch("apps.domain_security.scanner.dns") as mock_dns:
            mock_dns.resolver.resolve.return_value = [MagicMock(address="1.2.3.4")]
            with patch("apps.domain_security.scanner.dns.zone.from_xfr", return_value=mock_zone):
                with patch("apps.domain_security.scanner.dns.query.xfr"):
                    findings = _check_zone_transfer(session, "example.com", ns_records)

        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "zone transfer allowed" in findings[0].title.lower()

    def test_zone_transfer_refused_no_finding(self, db):
        from apps.domain_security.scanner import _check_zone_transfer
        session = self._make_session(db)

        ns_records = self._mock_ns()

        with patch("apps.domain_security.scanner.dns") as mock_dns:
            mock_dns.resolver.resolve.return_value = [MagicMock(address="1.2.3.4")]
            with patch("apps.domain_security.scanner.dns.zone.from_xfr",
                       side_effect=Exception("Transfer refused")):
                with patch("apps.domain_security.scanner.dns.query.xfr"):
                    findings = _check_zone_transfer(session, "example.com", ns_records)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MTA-STS checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestMTASTSChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_missing_mta_sts_creates_medium_finding(self, db):
        from apps.domain_security.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record", return_value=[]):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "MTA-STS not configured" in findings[0].title

    def test_mta_sts_testing_mode_creates_low_finding(self, db):
        from apps.domain_security.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record",
                   return_value=["v=STSv1; id=20240101; mode=testing"]):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "low"

    def test_mta_sts_enforce_mode_no_finding(self, db):
        from apps.domain_security.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record",
                   return_value=["v=STSv1; id=20240101; mode=enforce"]):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# TLS-RPT checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestTLSRPTChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_missing_tls_rpt_creates_low_finding(self, db):
        from apps.domain_security.scanner import _check_tls_rpt
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record", return_value=[]):
            findings = _check_tls_rpt(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "TLS-RPT" in findings[0].title

    def test_tls_rpt_present_no_finding(self, db):
        from apps.domain_security.scanner import _check_tls_rpt
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record",
                   return_value=["v=TLSRPTv1; rua=mailto:tls@example.com"]):
            findings = _check_tls_rpt(session, "example.com")

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Lame delegation checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestLameDelegationChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def _mock_ns(self, ns_host="ns1.example.com"):
        ns = MagicMock()
        ns.target = MagicMock()
        ns.target.__str__ = lambda s: f"{ns_host}."
        return [ns]

    def test_authoritative_ns_no_finding(self, db):
        from apps.domain_security.scanner import _check_lame_delegation
        import dns.flags
        session = self._make_session(db)
        ns_records = self._mock_ns()

        mock_response = MagicMock()
        mock_response.flags = dns.flags.AA  # AA bit set — authoritative
        mock_response.rcode.return_value = 0  # NOERROR

        with patch("apps.domain_security.scanner.dns.resolver.resolve") as mock_resolve:
            mock_resolve.return_value = [MagicMock(address="1.2.3.4")]
            with patch("apps.domain_security.scanner.dns.message.make_query"):
                with patch("apps.domain_security.scanner.dns.query.udp", return_value=mock_response):
                    findings = _check_lame_delegation(session, "example.com", ns_records)

        assert len(findings) == 0

    def test_non_authoritative_ns_creates_high_finding(self, db):
        from apps.domain_security.scanner import _check_lame_delegation
        session = self._make_session(db)
        ns_records = self._mock_ns()

        mock_response = MagicMock()
        mock_response.flags = 0  # AA bit NOT set — non-authoritative

        with patch("apps.domain_security.scanner.dns.resolver.resolve") as mock_resolve:
            mock_resolve.return_value = [MagicMock(address="1.2.3.4")]
            with patch("apps.domain_security.scanner.dns.message.make_query"):
                with patch("apps.domain_security.scanner.dns.query.udp", return_value=mock_response):
                    findings = _check_lame_delegation(session, "example.com", ns_records)

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "Lame delegation" in findings[0].title

    def test_ns_with_no_a_record_creates_high_finding(self, db):
        from apps.domain_security.scanner import _check_lame_delegation
        session = self._make_session(db)
        ns_records = self._mock_ns("ghost-ns.example.com")

        with patch("apps.domain_security.scanner.dns.resolver.resolve",
                   side_effect=Exception("NXDOMAIN")):
            findings = _check_lame_delegation(session, "example.com", ns_records)

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "no A record" in findings[0].extra["lame_servers"][0]

    def test_ns_timeout_counts_as_lame(self, db):
        from apps.domain_security.scanner import _check_lame_delegation
        session = self._make_session(db)
        ns_records = self._mock_ns()

        with patch("apps.domain_security.scanner.dns.resolver.resolve") as mock_resolve:
            mock_resolve.return_value = [MagicMock(address="1.2.3.4")]
            with patch("apps.domain_security.scanner.dns.message.make_query"):
                with patch("apps.domain_security.scanner.dns.query.udp",
                           side_effect=Exception("timed out")):
                    findings = _check_lame_delegation(session, "example.com", ns_records)

        assert len(findings) == 1
        assert "timeout" in findings[0].extra["lame_servers"][0]


# ---------------------------------------------------------------------------
# BIMI checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestBIMIChecks:
    def _make_session(self, db):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_missing_bimi_creates_info_finding(self, db):
        from apps.domain_security.scanner import _check_bimi
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record", return_value=[]):
            findings = _check_bimi(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "BIMI" in findings[0].title

    def test_bimi_present_no_finding(self, db):
        from apps.domain_security.scanner import _check_bimi
        session = self._make_session(db)

        with patch("apps.domain_security.scanner._get_txt_record",
                   return_value=["v=BIMI1; l=https://example.com/logo.svg"]):
            findings = _check_bimi(session, "example.com")

        assert len(findings) == 0
