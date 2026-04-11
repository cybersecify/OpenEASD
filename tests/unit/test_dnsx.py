"""Unit tests for apps/dnsx — public IP filter, analyzer, scanner orchestration."""

from unittest.mock import MagicMock, patch

import pytest

from apps.dnsx.analyzer import _is_public, analyze
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
