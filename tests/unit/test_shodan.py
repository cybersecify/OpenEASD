"""Unit tests for apps/shodan — collector (both tiers), analyzer, scanner.

Shodan is a passive, BYOK exposure tool: with no key it uses the free InternetDB
endpoint; with SHODAN_API_KEY it uses the full host API. It must be fail-graceful
(never raise), and its CVE findings must carry extra["cve_ids"] so cve_intel
enriches them.
"""

import requests
import pytest
from unittest.mock import MagicMock, patch

from apps.shodan.analyzer import analyze
from apps.shodan.collector import collect
from apps.shodan.scanner import run_shodan


def _session():
    from apps.core.engine.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full")


def _add_ips(session, *addrs):
    from apps.core.data.assets.models import IPAddress
    for a in addrs:
        IPAddress.objects.create(session=session, address=a, version=4)


def _resp(status=200, json_body=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.json.return_value = json_body if json_body is not None else {}
    return r


# ---------------------------------------------------------------------------
# Collector — tier selection
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestShodanCollectorTiers:
    def test_no_ips_returns_empty(self, settings):
        settings.SHODAN_API_KEY = ""
        assert collect(_session()) == []

    def test_free_tier_used_when_no_key(self, settings):
        settings.SHODAN_API_KEY = ""
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        body = {"ip": "1.2.3.4", "ports": [22, 443], "cpes": [], "hostnames": [],
                "tags": [], "vulns": ["CVE-2021-1234"]}
        with patch("apps.shodan.collector.requests.get", return_value=_resp(json_body=body)) as g:
            results = collect(sess)
        assert g.call_args[0][0].startswith("https://internetdb.shodan.io/")
        assert results[0]["tier"] == "internetdb"
        assert results[0]["ports"] == [22, 443]
        assert results[0]["vulns"] == ["CVE-2021-1234"]

    def test_paid_tier_used_when_key_set(self, settings):
        settings.SHODAN_API_KEY = "testkey"
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        body = {"ip_str": "1.2.3.4", "ports": [443],
                "data": [{"port": 443, "product": "nginx", "version": "1.18", "transport": "tcp"}],
                "vulns": ["CVE-2021-1234"], "cpes": [], "hostnames": [], "tags": []}
        with patch("apps.shodan.collector.requests.get", return_value=_resp(json_body=body)) as g:
            results = collect(sess)
        assert g.call_args[0][0].startswith("https://api.shodan.io/shodan/host/")
        assert g.call_args.kwargs["params"]["key"] == "testkey"
        assert results[0]["tier"] == "host"
        assert results[0]["services"][0]["product"] == "nginx"

    def test_paid_tier_caps_ips(self, settings):
        settings.SHODAN_API_KEY = "testkey"
        settings.SHODAN_MAX_IPS = 2
        sess = _session()
        _add_ips(sess, "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")
        with patch("apps.shodan.collector.requests.get", return_value=_resp(json_body={})) as g:
            collect(sess)
        assert g.call_count == 2  # capped at SHODAN_MAX_IPS

    def test_free_tier_not_capped(self, settings):
        settings.SHODAN_API_KEY = ""
        settings.SHODAN_MAX_IPS = 2  # cap must NOT apply to the free path
        sess = _session()
        _add_ips(sess, "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")
        with patch("apps.shodan.collector.requests.get", return_value=_resp(json_body={})) as g:
            collect(sess)
        assert g.call_count == 4

    def test_host_api_vulns_dict_form(self, settings):
        settings.SHODAN_API_KEY = "k"
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        body = {"ports": [80], "data": [], "vulns": {"CVE-2020-1": {}, "CVE-2020-2": {}}}
        with patch("apps.shodan.collector.requests.get", return_value=_resp(json_body=body)):
            results = collect(sess)
        assert set(results[0]["vulns"]) == {"CVE-2020-1", "CVE-2020-2"}


# ---------------------------------------------------------------------------
# Collector — fail-graceful contract
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestShodanCollectorFailGraceful:
    def test_404_is_skipped_not_error(self, settings):
        settings.SHODAN_API_KEY = ""
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        with patch("apps.shodan.collector.requests.get", return_value=_resp(status=404)):
            assert collect(sess) == []  # no data, no crash

    def test_request_exception_skipped(self, settings):
        settings.SHODAN_API_KEY = ""
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        with patch("apps.shodan.collector.requests.get",
                   side_effect=requests.RequestException("boom")):
            assert collect(sess) == []  # must NOT raise

    def test_non_200_skipped(self, settings):
        settings.SHODAN_API_KEY = ""
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        with patch("apps.shodan.collector.requests.get", return_value=_resp(status=500)):
            assert collect(sess) == []

    def test_429_retries_then_gives_up(self, settings):
        settings.SHODAN_API_KEY = ""
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        with patch("apps.shodan.collector.requests.get", return_value=_resp(status=429, headers={"Retry-After": "0"})), \
             patch("apps.shodan.collector.time.sleep"):
            assert collect(sess) == []  # exhausts retries, returns empty, no raise

    def test_bad_json_skipped(self, settings):
        settings.SHODAN_API_KEY = ""
        sess = _session()
        _add_ips(sess, "1.2.3.4")
        r = _resp(status=200)
        r.json.side_effect = ValueError("not json")
        with patch("apps.shodan.collector.requests.get", return_value=r):
            assert collect(sess) == []


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestShodanAnalyzer:
    def test_builds_exposure_finding(self):
        sess = _session()
        results = [{"ip": "1.2.3.4", "tier": "internetdb", "ports": [22, 443],
                    "services": [], "vulns": [], "hostnames": [], "tags": []}]
        findings = analyze(sess, results)
        exp = [f for f in findings if f.check_type == "shodan_exposure"]
        assert len(exp) == 1
        assert exp[0].source == "shodan"
        assert exp[0].target == "1.2.3.4"
        assert exp[0].extra["ports"] == [22, 443]

    def test_cve_finding_carries_cve_ids_for_enrichment(self):
        sess = _session()
        results = [{"ip": "1.2.3.4", "tier": "internetdb", "ports": [443],
                    "services": [], "vulns": ["CVE-2021-1", "CVE-2021-2"],
                    "hostnames": [], "tags": []}]
        findings = analyze(sess, results)
        cve = [f for f in findings if f.check_type == "cve"]
        assert len(cve) == 1
        # cve_intel enriches via extra["cve_ids"] — this MUST be present.
        assert cve[0].extra["cve_ids"] == ["CVE-2021-1", "CVE-2021-2"]
        # Version-approximate/unconfirmed banner match — low, not medium.
        assert cve[0].severity == "low"

    def test_no_finding_when_no_ports_and_no_vulns(self):
        sess = _session()
        results = [{"ip": "1.2.3.4", "tier": "internetdb", "ports": [],
                    "services": [], "vulns": [], "hostnames": [], "tags": []}]
        assert analyze(sess, results) == []

    def test_invalid_cves_filtered(self):
        sess = _session()
        results = [{"ip": "1.2.3.4", "tier": "internetdb", "ports": [80],
                    "services": [], "vulns": ["CVE-2021-1", "not-a-cve", ""],
                    "hostnames": [], "tags": []}]
        cve = [f for f in analyze(sess, results) if f.check_type == "cve"]
        assert cve[0].extra["cve_ids"] == ["CVE-2021-1"]

    def test_skips_non_dict_and_ipless_records(self):
        sess = _session()
        results = ["junk", {"tier": "internetdb", "ports": [80]}]  # no ip
        assert analyze(sess, results) == []

    def test_cdn_edge_ip_skips_exposure_finding(self):
        # A Cloudflare edge IP (104.16.0.0/13) — ports 80/443 there are the CDN's,
        # not the target's; no "exposed services" finding should be emitted.
        sess = _session()
        results = [{"ip": "104.21.55.55", "tier": "internetdb", "ports": [80, 443],
                    "services": [], "vulns": [], "hostnames": [], "tags": []}]
        exp = [f for f in analyze(sess, results) if f.check_type == "shodan_exposure"]
        assert exp == []

    def test_cdn_edge_ipv6_skips_exposure_finding(self):
        sess = _session()
        results = [{"ip": "2606:4700:3037::6815:3737", "tier": "internetdb",
                    "ports": [80, 443], "services": [], "vulns": [], "hostnames": [], "tags": []}]
        exp = [f for f in analyze(sess, results) if f.check_type == "shodan_exposure"]
        assert exp == []

    def test_cdn_edge_ip_still_reports_cve(self):
        # Exposure is skipped on a CDN edge, but a CVE is high-signal — keep it.
        sess = _session()
        results = [{"ip": "104.21.55.55", "tier": "internetdb", "ports": [443],
                    "services": [], "vulns": ["CVE-2021-1"], "hostnames": [], "tags": []}]
        findings = analyze(sess, results)
        assert [f for f in findings if f.check_type == "shodan_exposure"] == []
        assert [f for f in findings if f.check_type == "cve"] != []

    def test_non_web_port_gets_individual_exposure(self):
        # A non-web port (e.g. 3306 MySQL) is the actionable signal — individual.
        sess = _session()
        results = [{"ip": "1.2.3.4", "tier": "internetdb", "ports": [443, 3306],
                    "services": [], "vulns": [], "hostnames": [], "tags": []}]
        exp = [f for f in analyze(sess, results) if f.check_type == "shodan_exposure"]
        assert len(exp) == 1
        assert exp[0].target == "1.2.3.4"

    def test_web_only_host_is_collapsed_into_rollup(self):
        # 80/443 only on a non-CDN IP is just a web endpoint — no individual
        # "exposed services" finding; it lands in one web-exposure rollup instead.
        sess = _session()
        results = [{"ip": "1.2.3.4", "tier": "internetdb", "ports": [80, 443],
                    "services": [], "vulns": [], "hostnames": [], "tags": []}]
        out = analyze(sess, results)
        assert [f for f in out if f.check_type == "shodan_exposure"] == []
        roll = [f for f in out if f.check_type == "shodan_web_exposure"]
        assert len(roll) == 1
        assert roll[0].severity == "info"
        assert roll[0].extra["host_count"] == 1
        assert roll[0].extra["hosts"][0]["ip"] == "1.2.3.4"

    def test_cloudflare_alt_ports_are_web_only(self):
        # The cPanel-looking ports 2082/2083/8880 are Cloudflare's alt-HTTP ports.
        sess = _session()
        results = [{"ip": "1.2.3.4", "tier": "internetdb", "ports": [2082, 2083, 8880],
                    "services": [], "vulns": [], "hostnames": [], "tags": []}]
        out = analyze(sess, results)
        assert [f for f in out if f.check_type == "shodan_exposure"] == []
        assert len([f for f in out if f.check_type == "shodan_web_exposure"]) == 1

    def test_web_only_rollup_collapses_many_into_one(self):
        sess = _session()
        results = [{"ip": f"1.2.3.{i}", "tier": "internetdb", "ports": [443],
                    "services": [], "vulns": [], "hostnames": [], "tags": []} for i in range(1, 6)]
        roll = [f for f in analyze(sess, results) if f.check_type == "shodan_web_exposure"]
        assert len(roll) == 1 and roll[0].extra["host_count"] == 5


    def test_empty_results(self):
        assert analyze(_session(), []) == []


class TestIsCdnIp:
    def test_cloudflare_ipv4_and_ipv6(self):
        from apps.shodan.cdn import is_cdn_ip
        assert is_cdn_ip("104.21.55.55") == "Cloudflare"
        assert is_cdn_ip("2606:4700:3037::6815:3737") == "Cloudflare"

    def test_non_cdn_and_bad_input_return_none(self):
        from apps.shodan.cdn import is_cdn_ip
        assert is_cdn_ip("1.2.3.4") is None
        assert is_cdn_ip("8.8.8.8") is None
        assert is_cdn_ip("not-an-ip") is None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestShodanScanner:
    def test_saves_findings(self):
        from apps.core.data.findings.models import Finding
        sess = _session()
        with patch("apps.shodan.scanner.collect", return_value=[
            {"ip": "1.2.3.4", "tier": "internetdb", "ports": [443],
             "services": [], "vulns": ["CVE-2021-1"], "hostnames": [], "tags": []},
        ]):
            saved = run_shodan(sess)
        assert len(saved) == 2  # exposure + cve
        assert Finding.objects.filter(session=sess, source="shodan").count() == 2

    def test_empty_when_no_data(self):
        sess = _session()
        with patch("apps.shodan.scanner.collect", return_value=[]):
            assert run_shodan(sess) == []

    def test_never_raises_on_collect_error(self):
        sess = _session()
        with patch("apps.shodan.scanner.collect", side_effect=RuntimeError("boom")):
            assert run_shodan(sess) == []  # swallowed — must never fail a scan
