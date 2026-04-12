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
        from apps.core.findings.models import Finding

        session = ScanSession.objects.create(domain="secure.com", scan_type="full", status="pending")
        findings = self._run_mocked_scan(session)

        titles = [f.title for f in findings]
        # DNSSEC is mocked as always missing — only that finding expected
        assert "DNSSEC not enabled" in titles
        assert "SPF record missing" not in titles
        assert "DMARC record missing" not in titles
        # All findings saved to DB
        assert Finding.objects.filter(session=session).count() == len(findings)

    def test_missing_email_records_creates_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding

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
        from apps.core.findings.models import Finding

        session = ScanSession.objects.create(domain="dbtest.com", scan_type="full", status="pending")
        findings = self._run_mocked_scan(session, spf=None, dmarc=None)

        db_count = Finding.objects.filter(session=session).count()
        assert db_count == len(findings)
        assert db_count > 0


def _ensure_default_workflow():
    """Create the default Full Scan workflow (data migration doesn't run in test DBs)."""
    from apps.core.workflows.models import Workflow, WorkflowStep
    wf, created = Workflow.objects.get_or_create(
        name="Full Scan", defaults={"is_default": True, "description": "Test default workflow"},
    )
    if created:
        tools = [
            "domain_security", "subfinder", "dnsx", "naabu", "service_detection",
            "httpx", "nmap", "tls_checker", "ssh_checker", "nuclei", "web_checker",
        ]
        for order, tool in enumerate(tools, start=1):
            WorkflowStep.objects.create(workflow=wf, tool=tool, order=order, enabled=True)
    return wf


def _patch_all_tool_collectors():
    """Patch all tool collectors to return empty data (no binaries needed)."""
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(patch("apps.subfinder.scanner.collect", return_value=[]))
    stack.enter_context(patch("apps.dnsx.scanner.collect", return_value=[]))
    stack.enter_context(patch("apps.naabu.scanner.collect", return_value=[]))
    stack.enter_context(patch("apps.core.service_detection.detector._probe_tls", return_value=False))
    stack.enter_context(patch("apps.core.service_detection.detector._probe_http", return_value=False))
    stack.enter_context(patch("apps.httpx.scanner.collect", return_value=[]))
    stack.enter_context(patch("apps.nmap.scanner.collect", return_value={}))
    stack.enter_context(patch("apps.tls_checker.scanner.collect", return_value=[]))
    stack.enter_context(patch("apps.ssh_checker.scanner.collect", return_value=[]))
    stack.enter_context(patch("apps.nuclei.scanner.collect", return_value=[]))
    stack.enter_context(patch("apps.web_checker.scanner.collect", return_value=[]))
    return stack


@pytest.mark.django_db
class TestFullScanPipeline:
    """Tests run_scan orchestration → domain_security → insights."""

    def test_run_scan_completes_session(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan

        wf = _ensure_default_workflow()
        session = ScanSession.objects.create(domain="pipeline.com", scan_type="full", status="pending", workflow=wf)

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

        with _patch_all_tool_collectors(), \
             patch("apps.domain_security.scanner._resolve", side_effect=mock_resolve), \
             patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt), \
             patch("apps.domain_security.scanner.dns") as mock_dns, \
             patch("apps.domain_security.scanner.dns.zone.from_xfr", side_effect=Exception("refused")), \
             patch("apps.domain_security.scanner.dns.query.xfr"), \
             patch("apps.domain_security.scanner.requests.get", return_value=mock_rdap):
            mock_dns.resolver.resolve.side_effect = Exception("no DNSKEY")
            run_scan(session.id)

        session.refresh_from_db()
        assert session.status == "completed"
        assert session.end_time is not None

    def test_run_scan_builds_insights(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan
        from apps.core.insights.models import ScanSummary

        wf = _ensure_default_workflow()
        session = ScanSession.objects.create(domain="insights-test.com", scan_type="full", status="pending", workflow=wf)

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

        with _patch_all_tool_collectors(), \
             patch("apps.domain_security.scanner._resolve", side_effect=mock_resolve), \
             patch("apps.domain_security.scanner._get_txt_record", side_effect=mock_txt), \
             patch("apps.domain_security.scanner.dns") as mock_dns, \
             patch("apps.domain_security.scanner.dns.zone.from_xfr", side_effect=Exception("refused")), \
             patch("apps.domain_security.scanner.dns.query.xfr"), \
             patch("apps.domain_security.scanner.requests.get", return_value=mock_rdap):
            mock_dns.resolver.resolve.side_effect = Exception("no DNSKEY")
            run_scan(session.id)

        assert ScanSummary.objects.filter(session=session).exists()
        summary = ScanSummary.objects.get(session=session)
        assert summary.total_findings > 0

    def test_run_scan_detects_deltas_on_second_scan(self, db):
        from apps.core.scans.models import ScanSession, ScanDelta
        from apps.core.scans.pipeline import run_scan

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
        wf = _ensure_default_workflow()
        s1 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="pending", workflow=wf)
        mr, mt, mrdap = make_mocks()
        with _patch_all_tool_collectors(), \
             patch("apps.domain_security.scanner._resolve", side_effect=mr), \
             patch("apps.domain_security.scanner._get_txt_record", side_effect=mt), \
             patch("apps.domain_security.scanner.dns") as mdns, \
             patch("apps.domain_security.scanner.dns.zone.from_xfr", side_effect=Exception("refused")), \
             patch("apps.domain_security.scanner.dns.query.xfr"), \
             patch("apps.domain_security.scanner.requests.get", return_value=mrdap):
            mdns.resolver.resolve.side_effect = Exception("no DNSKEY")
            run_scan(s1.id)

        # Second scan — same config (findings should be the same, delta = 0 new)
        s2 = ScanSession.objects.create(domain="delta.com", scan_type="full", status="pending", workflow=wf)
        mr2, mt2, mrdap2 = make_mocks()
        with _patch_all_tool_collectors(), \
             patch("apps.domain_security.scanner._resolve", side_effect=mr2), \
             patch("apps.domain_security.scanner._get_txt_record", side_effect=mt2), \
             patch("apps.domain_security.scanner.dns") as mdns2, \
             patch("apps.domain_security.scanner.dns.zone.from_xfr", side_effect=Exception("refused")), \
             patch("apps.domain_security.scanner.dns.query.xfr"), \
             patch("apps.domain_security.scanner.requests.get", return_value=mrdap2):
            mdns2.resolver.resolve.side_effect = Exception("no DNSKEY")
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
        from apps.core.findings.models import Finding
        from apps.core.insights.models import ScanSummary
        from django.urls import reverse

        domain = Domain.objects.create(name="cascade.com", is_primary=True)
        session = ScanSession.objects.create(
            domain="cascade.com", scan_type="full", status="completed",
            end_time=timezone.now()
        )
        Finding.objects.create(session=session, source="domain_security", target="cascade.com", check_type="dns", severity="high", title="No MX"
        )
        ScanSummary.objects.create(
            session=session, domain="cascade.com",
            scan_date=timezone.now(), total_findings=1, high_count=1
        )

        auth_client.post(reverse("domain-delete", args=[domain.pk]))

        assert not Domain.objects.filter(name="cascade.com").exists()
        assert not ScanSession.objects.filter(domain="cascade.com").exists()
        assert not Finding.objects.filter(source="domain_security", target="cascade.com").exists()
        assert not ScanSummary.objects.filter(domain="cascade.com").exists()

    def test_delete_domain_cascades_all_assets(self, auth_client, db):
        """Regression test: deleting a domain must clean up subdomains, IPs, ports, URLs, NmapFindings."""
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL
        from apps.core.findings.models import Finding
        from django.urls import reverse

        domain = Domain.objects.create(name="cascade.com", is_primary=True)
        session = ScanSession.objects.create(
            domain="cascade.com", scan_type="full", status="completed",
            end_time=timezone.now(),
        )
        sub = Subdomain.objects.create(session=session, domain="cascade.com", subdomain="api.cascade.com", source="subfinder")
        ip = IPAddress.objects.create(session=session, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(session=session, ip_address=ip, address="1.2.3.4", port=22, protocol="tcp", state="open", source="naabu")
        URL.objects.create(session=session, port=port, subdomain=sub, url="http://api.cascade.com:80", host="api.cascade.com", port_number=80, source="httpx")
        Finding.objects.create(
            session=session, source="nmap", check_type="cve", port=port,
            target="1.2.3.4:22", severity="high", title="CVE-2024-6387",
            extra={"cve": "CVE-2024-6387", "cvss_score": 8.1, "address": "1.2.3.4", "port_number": 22},
        )

        auth_client.post(reverse("domain-delete", args=[domain.pk]))

        # All asset types must be gone
        assert Subdomain.objects.filter(session=session).count() == 0
        assert IPAddress.objects.filter(session=session).count() == 0
        assert Port.objects.filter(session=session).count() == 0
        assert URL.objects.filter(session=session).count() == 0
        assert Finding.objects.filter(session=session, source="nmap").count() == 0


@pytest.mark.django_db
class TestFullPipelineMocked:
    """Integration test for the full 6-phase pipeline with all tools mocked."""

    def _mock_all_tools(self):
        """Patch every collector + the dns/rdap calls so run_scan completes deterministically."""
        import datetime
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        mock_rdap = MagicMock()
        mock_rdap.json.return_value = {
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}],
        }

        def mock_resolve(domain, record_type):
            return ["1.2.3.4"] if record_type in ("A", "NS", "MX") else []

        def mock_txt(domain):
            if "_dmarc" in domain:
                return ["v=DMARC1; p=reject"]
            if "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=abc"]
            return ["v=spf1 -all"]

        # Tool collectors return canned data
        subfinder_records = [
            {"host": "www.pipeline.test", "ip": None},
            {"host": "api.pipeline.test", "ip": None},
        ]
        dnsx_records = [
            {"host": "www.pipeline.test", "a": ["1.2.3.4"], "aaaa": []},
            {"host": "api.pipeline.test", "a": ["5.6.7.8"], "aaaa": []},
        ]
        naabu_records = [
            {"host": "1.2.3.4", "port": 80, "protocol": "tcp"},
            {"host": "1.2.3.4", "port": 22, "protocol": "tcp"},
            {"host": "5.6.7.8", "port": 443, "protocol": "tcp"},
        ]
        httpx_records = [
            {"url": "http://www.pipeline.test:80", "host": "www.pipeline.test", "host_ip": "1.2.3.4", "port": "80", "status_code": 200},
            {"url": "https://api.pipeline.test:443", "host": "api.pipeline.test", "host_ip": "5.6.7.8", "port": "443", "status_code": 200},
        ]

        return {
            "rdap": mock_rdap,
            "resolve": mock_resolve,
            "txt": mock_txt,
            "subfinder": subfinder_records,
            "dnsx": dnsx_records,
            "naabu": naabu_records,
            "httpx": httpx_records,
        }

    def test_full_pipeline_produces_correct_asset_graph(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL

        wf = _ensure_default_workflow()
        session = ScanSession.objects.create(domain="pipeline.test", scan_type="full", status="pending", workflow=wf)
        m = self._mock_all_tools()

        with patch("apps.domain_security.scanner._resolve", side_effect=m["resolve"]), \
             patch("apps.domain_security.scanner._get_txt_record", side_effect=m["txt"]), \
             patch("apps.domain_security.scanner.dns") as mdns, \
             patch("apps.domain_security.scanner.dns.zone.from_xfr", side_effect=Exception("refused")), \
             patch("apps.domain_security.scanner.dns.query.xfr"), \
             patch("apps.domain_security.scanner.requests.get", return_value=m["rdap"]), \
             patch("apps.subfinder.scanner.collect", return_value=m["subfinder"]), \
             patch("apps.dnsx.scanner.collect", return_value=m["dnsx"]), \
             patch("apps.naabu.scanner.collect", return_value=m["naabu"]), \
             patch("apps.core.service_detection.detector._probe_tls", return_value=False), \
             patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.httpx.scanner.collect", return_value=m["httpx"]), \
             patch("apps.nmap.scanner.collect", return_value={}), \
             patch("apps.tls_checker.scanner.collect", return_value=[]), \
             patch("apps.ssh_checker.scanner.collect", return_value=[]), \
             patch("apps.nuclei.scanner.collect", return_value=[]), \
             patch("apps.web_checker.scanner.collect", return_value=[]):
            mdns.resolver.resolve.side_effect = Exception("no DNSKEY")
            run_scan(session.id)

        session.refresh_from_db()
        assert session.status == "completed"

        # Verify the asset graph is intact
        assert Subdomain.objects.filter(session=session).count() == 2
        assert Subdomain.objects.filter(session=session, is_active=True).count() == 2
        assert IPAddress.objects.filter(session=session).count() == 2
        assert Port.objects.filter(session=session).count() == 3
        assert URL.objects.filter(session=session).count() == 2

    def test_full_pipeline_classifies_web_vs_non_web_correctly(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan
        from apps.core.assets.models import Port

        def mock_tls(ip, port):
            return port in (443,)

        def mock_http(ip, port, scheme):
            return port in (80, 443)

        wf = _ensure_default_workflow()
        session = ScanSession.objects.create(domain="pipeline.test", scan_type="full", status="pending", workflow=wf)
        m = self._mock_all_tools()

        with patch("apps.domain_security.scanner._resolve", side_effect=m["resolve"]), \
             patch("apps.domain_security.scanner._get_txt_record", side_effect=m["txt"]), \
             patch("apps.domain_security.scanner.dns") as mdns, \
             patch("apps.domain_security.scanner.dns.zone.from_xfr", side_effect=Exception("refused")), \
             patch("apps.domain_security.scanner.dns.query.xfr"), \
             patch("apps.domain_security.scanner.requests.get", return_value=m["rdap"]), \
             patch("apps.subfinder.scanner.collect", return_value=m["subfinder"]), \
             patch("apps.dnsx.scanner.collect", return_value=m["dnsx"]), \
             patch("apps.naabu.scanner.collect", return_value=m["naabu"]), \
             patch("apps.core.service_detection.detector._probe_tls", side_effect=mock_tls), \
             patch("apps.core.service_detection.detector._probe_http", side_effect=mock_http), \
             patch("apps.httpx.scanner.collect", return_value=m["httpx"]), \
             patch("apps.nmap.scanner.collect", return_value={}), \
             patch("apps.tls_checker.scanner.collect", return_value=[]), \
             patch("apps.ssh_checker.scanner.collect", return_value=[]), \
             patch("apps.nuclei.scanner.collect", return_value=[]), \
             patch("apps.web_checker.scanner.collect", return_value=[]):
            mdns.resolver.resolve.side_effect = Exception("no DNSKEY")
            run_scan(session.id)

        # Web ports (service_detection sets is_web=True for http/https)
        web_ports = Port.objects.filter(session=session, is_web=True)
        web_pairs = {(p.address, p.port) for p in web_ports}
        assert ("1.2.3.4", 80) in web_pairs
        assert ("5.6.7.8", 443) in web_pairs
        # Non-web port: 1.2.3.4:22 (SSH)
        assert ("1.2.3.4", 22) not in web_pairs

    def test_full_pipeline_total_findings_includes_all_tools(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import run_scan
        from apps.core.insights.models import ScanSummary

        wf = _ensure_default_workflow()
        session = ScanSession.objects.create(domain="pipeline.test", scan_type="full", status="pending", workflow=wf)
        m = self._mock_all_tools()

        with patch("apps.domain_security.scanner._resolve", side_effect=m["resolve"]), \
             patch("apps.domain_security.scanner._get_txt_record", side_effect=m["txt"]), \
             patch("apps.domain_security.scanner.dns") as mdns, \
             patch("apps.domain_security.scanner.dns.zone.from_xfr", side_effect=Exception("refused")), \
             patch("apps.domain_security.scanner.dns.query.xfr"), \
             patch("apps.domain_security.scanner.requests.get", return_value=m["rdap"]), \
             patch("apps.subfinder.scanner.collect", return_value=m["subfinder"]), \
             patch("apps.dnsx.scanner.collect", return_value=m["dnsx"]), \
             patch("apps.naabu.scanner.collect", return_value=m["naabu"]), \
             patch("apps.core.service_detection.detector._probe_tls", return_value=False), \
             patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.httpx.scanner.collect", return_value=m["httpx"]), \
             patch("apps.nmap.scanner.collect", return_value={}), \
             patch("apps.tls_checker.scanner.collect", return_value=[]), \
             patch("apps.ssh_checker.scanner.collect", return_value=[]), \
             patch("apps.nuclei.scanner.collect", return_value=[]), \
             patch("apps.web_checker.scanner.collect", return_value=[]):
            mdns.resolver.resolve.side_effect = Exception("no DNSKEY")
            run_scan(session.id)

        summary = ScanSummary.objects.get(session=session)
        # tool_breakdown has both domain_security and nmap (nmap=0 here, no findings)
        assert "domain_security" in summary.tool_breakdown
        assert summary.tool_breakdown["domain_security"] > 0
        # Total should equal sum of tool_breakdown (regression test for the
        # off-by-one bug where info-severity findings were excluded from total)
        assert summary.total_findings == sum(summary.tool_breakdown.values())
