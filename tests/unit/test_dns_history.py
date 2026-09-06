"""Tests for the dns_history passive tool (collector, analyzer, scanner)."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from apps.dns_history import collector as dns_collector
from apps.dns_history.analyzer import analyze
from apps.dns_history.scanner import run_dns_history


def _resp(status=200, json_data=None, raise_json=False):
    r = MagicMock()
    r.status_code = status
    if raise_json:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = json_data if json_data is not None else []
    return r


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class TestCollector:
    def test_no_url_configured_returns_empty(self, settings):
        settings.DNS_HISTORY_API_URL = ""
        assert dns_collector.collect("example.com") == []

    def test_request_exception_returns_empty(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        with patch.object(dns_collector.requests, "get",
                          side_effect=requests.RequestException("boom")):
            assert dns_collector.collect("example.com") == []

    def test_non_200_returns_empty(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        with patch.object(dns_collector.requests, "get", return_value=_resp(status=500)):
            assert dns_collector.collect("example.com") == []

    def test_bad_json_returns_empty(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        with patch.object(dns_collector.requests, "get",
                          return_value=_resp(raise_json=True)):
            assert dns_collector.collect("example.com") == []

    def test_happy_path_parses_records(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        payload = [
            {"type": "A", "value": "1.2.3.4", "first_seen": "2020", "last_seen": "2022"},
            {"type": "mx", "value": "mail.old.com"},
        ]
        with patch.object(dns_collector.requests, "get", return_value=_resp(json_data=payload)):
            out = dns_collector.collect("example.com")
        assert {r["type"] for r in out} == {"A", "MX"}
        assert out[0]["value"] == "1.2.3.4"
        assert out[0]["first_seen"] == "2020"

    def test_accepts_wrapped_dict(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        payload = {"records": [{"type": "A", "value": "9.9.9.9"}]}
        with patch.object(dns_collector.requests, "get", return_value=_resp(json_data=payload)):
            out = dns_collector.collect("example.com")
        assert out == [{"type": "A", "value": "9.9.9.9", "first_seen": "", "last_seen": ""}]

    def test_filters_unknown_types_and_empty_values(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        payload = [
            {"type": "TXT", "value": "v=spf1"},   # unsupported type
            {"type": "A", "value": ""},            # empty value
            {"type": "AAAA", "value": "::1"},      # kept
        ]
        with patch.object(dns_collector.requests, "get", return_value=_resp(json_data=payload)):
            out = dns_collector.collect("example.com")
        assert out == [{"type": "AAAA", "value": "::1", "first_seen": "", "last_seen": ""}]

    def test_dedupes_records(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        payload = [{"type": "A", "value": "1.1.1.1"}, {"type": "A", "value": "1.1.1.1"}]
        with patch.object(dns_collector.requests, "get", return_value=_resp(json_data=payload)):
            assert len(dns_collector.collect("example.com")) == 1

    def test_sends_honest_user_agent(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        settings.OPENEASD_USER_AGENT = "OpenEASD/test-ua"
        with patch.object(dns_collector.requests, "get", return_value=_resp(json_data=[])) as g:
            dns_collector.collect("example.com")
        assert g.call_args.kwargs["headers"]["User-Agent"] == "OpenEASD/test-ua"

    def test_record_cap(self, settings):
        settings.DNS_HISTORY_API_URL = "https://pdns.example/api"
        payload = [{"type": "A", "value": f"10.0.0.{i}"} for i in range(200)]
        with patch.object(dns_collector.requests, "get", return_value=_resp(json_data=payload)):
            assert len(dns_collector.collect("example.com")) == dns_collector._MAX_RECORDS


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalyzer:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_empty_records_returns_empty(self):
        assert analyze(self._session(), "example.com", []) == []

    def test_builds_info_finding_per_record(self):
        sess = self._session()
        records = [
            {"type": "A", "value": "1.2.3.4", "first_seen": "2020", "last_seen": "2022"},
            {"type": "MX", "value": "mail.old.com", "first_seen": "", "last_seen": ""},
        ]
        findings = analyze(sess, "example.com", records)
        assert len(findings) == 2
        f = findings[0]
        assert f.source == "dns_history"
        assert f.check_type == "dns_history"
        assert f.severity == "info"
        assert "1.2.3.4" in f.title
        assert f.target == "example.com"
        assert f.extra["record_type"] == "A"
        assert f.extra["value"] == "1.2.3.4"

    def test_skips_records_without_value(self):
        sess = self._session()
        findings = analyze(sess, "example.com", [{"type": "A", "value": ""}])
        assert findings == []


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def _session(self, domain="example.com"):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain=domain, scan_type="full")

    def test_no_domain_skips(self):
        sess = self._session(domain="")
        assert run_dns_history(sess) == []

    def test_no_records_saves_nothing(self):
        from apps.core.findings.models import Finding
        sess = self._session()
        with patch("apps.dns_history.scanner.collect", return_value=[]):
            assert run_dns_history(sess) == []
        assert not Finding.objects.filter(session=sess).exists()

    def test_happy_path_saves_and_returns(self):
        from apps.core.findings.models import Finding
        sess = self._session()
        records = [{"type": "A", "value": "1.2.3.4", "first_seen": "", "last_seen": ""}]
        with patch("apps.dns_history.scanner.collect", return_value=records):
            saved = run_dns_history(sess)
        assert len(saved) == 1
        assert Finding.objects.filter(session=sess, source="dns_history").count() == 1

    def test_never_raises_on_collect_error(self):
        sess = self._session()
        with patch("apps.dns_history.scanner.collect", side_effect=RuntimeError("boom")):
            assert run_dns_history(sess) == []  # swallowed
