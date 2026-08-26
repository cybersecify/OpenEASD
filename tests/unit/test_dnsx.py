"""Unit tests for apps/dnsx — public IP filter, analyzer, scanner orchestration."""

from unittest.mock import MagicMock, patch

import pytest

from apps.dnsx.analyzer import _is_cdn_ip, _is_public, analyze
from apps.dnsx.collector import collect
from apps.dnsx.scanner import run_dnsx


# ---------------------------------------------------------------------------
# Public IP filter
# ---------------------------------------------------------------------------

class TestIsPublic:
    """Pure-logic tests for the public IP classifier."""

    def test_public_ipv4(self):
        assert _is_public("8.8.8.8") is True
        assert _is_public("1.1.1.1") is True
        assert _is_public("54.23.45.67") is True

    def test_public_ipv6(self):
        assert _is_public("2606:4700:4700::1111") is True
        assert _is_public("2001:4860:4860::8888") is True

    def test_private_10(self):
        assert _is_public("10.0.0.5") is False
        assert _is_public("10.255.255.255") is False

    def test_private_172(self):
        assert _is_public("172.16.0.1") is False
        assert _is_public("172.31.255.255") is False

    def test_private_192_168(self):
        assert _is_public("192.168.1.1") is False
        assert _is_public("192.168.255.255") is False

    def test_loopback(self):
        assert _is_public("127.0.0.1") is False
        assert _is_public("::1") is False

    def test_link_local_ipv4(self):
        # AWS/Azure metadata IP — must never leak into the pipeline
        assert _is_public("169.254.169.254") is False

    def test_link_local_ipv6(self):
        assert _is_public("fe80::1") is False

    def test_multicast(self):
        assert _is_public("224.0.0.1") is False
        assert _is_public("ff02::1") is False

    def test_reserved(self):
        # 0.0.0.0/8 is reserved
        assert _is_public("0.0.0.1") is False

    def test_invalid_input(self):
        assert _is_public("not-an-ip") is False
        assert _is_public("") is False
        assert _is_public("999.999.999.999") is False


# ---------------------------------------------------------------------------
# CDN IP filter
# ---------------------------------------------------------------------------

class TestIsCdnIp:
    def test_cloudflare_ip_detected(self):
        # 172.67.191.147 is in Cloudflare's 172.64.0.0/13 range
        assert _is_cdn_ip("172.67.191.147") is True

    def test_cloudflare_ip_104_range(self):
        # 104.21.84.116 is in Cloudflare's 104.16.0.0/13 range
        assert _is_cdn_ip("104.21.84.116") is True

    def test_fastly_ip_detected(self):
        # 151.101.0.1 is in Fastly's 151.101.0.0/16 range
        assert _is_cdn_ip("151.101.0.1") is True

    def test_cloudfront_ip_detected(self):
        # 54.192.0.1 is in CloudFront's 54.192.0.0/16 range
        assert _is_cdn_ip("54.192.0.1") is True

    def test_regular_public_ip_not_cdn(self):
        assert _is_cdn_ip("8.8.8.8") is False

    def test_another_public_ip_not_cdn(self):
        assert _is_cdn_ip("54.23.45.67") is False

    def test_private_ip_not_cdn(self):
        assert _is_cdn_ip("10.0.0.1") is False

    def test_invalid_input(self):
        assert _is_cdn_ip("not-an-ip") is False


# ---------------------------------------------------------------------------
# Collector — mocked subprocess
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDnsxCollector:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def _fake(self, stdout, returncode=0):
        m = MagicMock()
        m.stdout = stdout
        m.returncode = returncode
        m.stderr = ""
        return m

    def test_returns_empty_for_no_subdomains(self):
        sess = self._session()
        # No subprocess should run when there is nothing to resolve.
        with patch("apps.dnsx.collector.subprocess.run") as run:
            assert collect(sess, []) == []
        assert not run.called

    def test_parses_json_lines(self):
        sess = self._session()
        stdout = (
            '{"host":"api.example.com","a":["54.23.45.67"],"aaaa":[]}\n'
            '{"host":"www.example.com","a":["93.184.216.34"],"aaaa":["2606:4700::1"]}\n'
        )
        with patch("apps.dnsx.collector.subprocess.run", return_value=self._fake(stdout)):
            records = collect(sess, ["api.example.com", "www.example.com"])
        assert len(records) == 2
        assert records[0] == {"host": "api.example.com", "a": ["54.23.45.67"], "aaaa": []}

    def test_skips_malformed_json_line(self):
        sess = self._session()
        stdout = (
            "this is not json\n"
            '{"host":"api.example.com","a":["54.23.45.67"],"aaaa":[]}\n'
        )
        with patch("apps.dnsx.collector.subprocess.run", return_value=self._fake(stdout)):
            records = collect(sess, ["api.example.com"])
        assert len(records) == 1
        assert records[0]["host"] == "api.example.com"

    def test_empty_stdout_returns_empty(self):
        sess = self._session()
        with patch("apps.dnsx.collector.subprocess.run", return_value=self._fake("")):
            records = collect(sess, ["api.example.com"])
        assert records == []

    def test_nxdomain_null_a_field_normalised_to_empty_list(self):
        # dnsx emits null for the "a"/"aaaa" arrays when a host does not resolve.
        # The collector must coerce null → [] so the analyzer never sees None.
        sess = self._session()
        stdout = '{"host":"dead.example.com","a":null,"aaaa":null}\n'
        with patch("apps.dnsx.collector.subprocess.run", return_value=self._fake(stdout)):
            records = collect(sess, ["dead.example.com"])
        assert records == [{"host": "dead.example.com", "a": [], "aaaa": []}]

    def test_record_without_host_skipped(self):
        sess = self._session()
        stdout = '{"a":["54.23.45.67"]}\n{"host":"ok.example.com","a":[]}\n'
        with patch("apps.dnsx.collector.subprocess.run", return_value=self._fake(stdout)):
            records = collect(sess, ["ok.example.com"])
        assert len(records) == 1
        assert records[0]["host"] == "ok.example.com"

    def test_binary_missing_raises(self):
        from apps.core.workflows.exceptions import ToolBinaryMissing
        sess = self._session()
        with patch("apps.dnsx.collector.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(ToolBinaryMissing):
                collect(sess, ["api.example.com"])

    def test_timeout_raises(self):
        import subprocess as sp
        from apps.core.workflows.exceptions import ToolTimeout
        sess = self._session()
        with patch("apps.dnsx.collector.subprocess.run",
                   side_effect=sp.TimeoutExpired(cmd="dnsx", timeout=300)):
            with pytest.raises(ToolTimeout):
                collect(sess, ["api.example.com"])


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDnsxAnalyzer:
    def _make_session_with_subdomains(self, hosts: list[str]):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        index = {}
        for host in hosts:
            sub = Subdomain.objects.create(
                session=sess, domain="example.com", subdomain=host, source="subfinder"
            )
            index[host] = sub
        return sess, index

    def test_analyze_creates_ip_objects_for_public_ips(self):
        sess, index = self._make_session_with_subdomains(["api.example.com"])
        records = [{"host": "api.example.com", "a": ["54.23.45.67"], "aaaa": []}]
        ips, activated = analyze(sess, records, index)
        assert len(ips) == 1
        assert ips[0].address == "54.23.45.67"
        assert ips[0].source == "dnsx"
        assert ips[0].version == 4
        assert len(activated) == 1
        assert activated[0].subdomain == "api.example.com"

    def test_analyze_filters_out_private_ips(self):
        sess, index = self._make_session_with_subdomains(["internal.example.com"])
        records = [{"host": "internal.example.com", "a": ["10.0.0.5"], "aaaa": []}]
        ips, activated = analyze(sess, records, index)
        assert ips == []
        assert activated == []

    def test_analyze_keeps_public_skips_private_in_mixed_list(self):
        sess, index = self._make_session_with_subdomains(["mixed.example.com"])
        records = [{
            "host": "mixed.example.com",
            "a": ["10.0.0.5", "54.23.45.67"],
            "aaaa": [],
        }]
        ips, activated = analyze(sess, records, index)
        assert len(ips) == 1
        assert ips[0].address == "54.23.45.67"
        assert len(activated) == 1

    def test_analyze_handles_ipv6(self):
        sess, index = self._make_session_with_subdomains(["v6.example.com"])
        records = [{"host": "v6.example.com", "a": [], "aaaa": ["2606:4700:4700::1111"]}]
        ips, activated = analyze(sess, records, index)
        assert len(ips) == 1
        assert ips[0].version == 6
        assert len(activated) == 1

    def test_analyze_dedupes_same_subdomain_ip_pair(self):
        sess, index = self._make_session_with_subdomains(["dup.example.com"])
        records = [{
            "host": "dup.example.com",
            "a": ["54.23.45.67", "54.23.45.67"],
            "aaaa": [],
        }]
        ips, _ = analyze(sess, records, index)
        assert len(ips) == 1

    def test_analyze_filters_cdn_ips_from_ip_records(self):
        # Cloudflare IP should not produce an IPAddress record
        sess, index = self._make_session_with_subdomains(["cdn.example.com"])
        records = [{"host": "cdn.example.com", "a": ["172.67.191.147"], "aaaa": []}]
        ips, activated = analyze(sess, records, index)
        assert ips == []
        # But the subdomain IS reachable so it gets activated
        assert len(activated) == 1

    def test_analyze_keeps_origin_ip_when_mixed_with_cdn(self):
        # If a subdomain has both a CDN IP and a real origin IP, keep the origin
        sess, index = self._make_session_with_subdomains(["mixed.example.com"])
        records = [{
            "host": "mixed.example.com",
            "a": ["172.67.191.147", "54.23.45.67"],
            "aaaa": [],
        }]
        ips, activated = analyze(sess, records, index)
        assert len(ips) == 1
        assert ips[0].address == "54.23.45.67"
        assert len(activated) == 1

    def test_analyze_skips_unknown_hosts(self):
        sess, index = self._make_session_with_subdomains(["known.example.com"])
        records = [{"host": "unknown.example.com", "a": ["8.8.8.8"], "aaaa": []}]
        ips, activated = analyze(sess, records, index)
        assert ips == []
        assert activated == []

    def test_analyze_no_resolution_means_not_active(self):
        sess, index = self._make_session_with_subdomains(["dead.example.com"])
        records = [{"host": "dead.example.com", "a": [], "aaaa": []}]
        ips, activated = analyze(sess, records, index)
        assert ips == []
        assert activated == []


# ---------------------------------------------------------------------------
# Scanner orchestrator (with mocked collector)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDnsxScanner:
    def test_run_dnsx_returns_empty_when_no_subdomains(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        result = run_dnsx(sess)
        assert result == []

    def test_run_dnsx_marks_active_and_creates_ips(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        Subdomain.objects.create(
            session=sess, domain="example.com", subdomain="api.example.com", source="subfinder"
        )

        with patch("apps.dnsx.scanner.collect", return_value=[
            {"host": "api.example.com", "a": ["54.23.45.67"], "aaaa": []}
        ]):
            activated = run_dnsx(sess)

        assert len(activated) == 1
        assert IPAddress.objects.filter(session=sess).count() == 1
        sub = Subdomain.objects.get(session=sess, subdomain="api.example.com")
        assert sub.is_active is True
        assert sub.resolved_at is not None

    def test_prunes_unresolved_alterx_candidates_only(self):
        # alterx invents names; a candidate that doesn't resolve must be pruned so
        # it can't inflate the subdomain count. Discovery-tool names (subfinder)
        # are kept even when unresolved — those are real observed names.
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        Subdomain.objects.create(session=sess, domain="example.com",
                                 subdomain="real.example.com", source="subfinder")     # resolves
        Subdomain.objects.create(session=sess, domain="example.com",
                                 subdomain="dead.example.com", source="subfinder")      # subfinder, no resolve -> KEEP
        Subdomain.objects.create(session=sess, domain="example.com",
                                 subdomain="live-guess.example.com", source="alterx")   # alterx, resolves -> KEEP
        Subdomain.objects.create(session=sess, domain="example.com",
                                 subdomain="dead-guess.example.com", source="alterx")   # alterx, no resolve -> PRUNE

        with patch("apps.dnsx.scanner.collect", return_value=[
            {"host": "real.example.com", "a": ["54.23.45.67"], "aaaa": []},
            {"host": "live-guess.example.com", "a": ["54.23.45.68"], "aaaa": []},
        ]):
            run_dnsx(sess)

        remaining = set(Subdomain.objects.filter(session=sess).values_list("subdomain", flat=True))
        assert "dead-guess.example.com" not in remaining      # pruned
        assert "real.example.com" in remaining                # resolved subfinder
        assert "dead.example.com" in remaining                # unresolved subfinder kept
        assert "live-guess.example.com" in remaining          # resolved alterx kept
        assert Subdomain.objects.filter(session=sess).count() == 3

    def test_run_dnsx_does_not_activate_subdomain_with_only_private_ips(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        Subdomain.objects.create(
            session=sess, domain="example.com", subdomain="internal.example.com", source="subfinder"
        )

        with patch("apps.dnsx.scanner.collect", return_value=[
            {"host": "internal.example.com", "a": ["10.0.0.5"], "aaaa": []}
        ]):
            activated = run_dnsx(sess)

        assert activated == []
        sub = Subdomain.objects.get(session=sess, subdomain="internal.example.com")
        assert sub.is_active is False
