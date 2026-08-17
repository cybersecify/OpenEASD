"""Unit tests for apps/httpx/waf.py — WAF/block/challenge classification (spec C1)."""

import pytest

from apps.httpx.waf import classify, fingerprint_vendor


class TestClassify:
    @pytest.mark.parametrize("status,title,server,expect_reach,expect_vendor", [
        # clean reach — a plain 200 behind no WAF
        (200, "Example Domain", "nginx", "reached", None),
        # a legitimate app 404 must NOT be treated as blocked
        (404, "Not Found", "nginx", "reached", None),
        # a legitimate app 403 with no WAF fingerprint is a real answer, not a block
        (403, "Forbidden", "Apache", "reached", None),
        # Cloudflare block: 403 + cloudflare server
        (403, "", "cloudflare", "blocked", "cloudflare"),
        # Cloudflare challenge page (JS interstitial) returns 200 with a giveaway title
        (200, "Just a moment...", "cloudflare", "challenged", "cloudflare"),
        # challenge title even without a known server → challenged + unidentified
        (200, "Attention Required!", "", "challenged", "unidentified"),
        # rate limited by anyone
        (429, "", "nginx", "rate_limited", "unidentified"),
        # Akamai block
        (403, "", "AkamaiGHost", "blocked", "akamai"),
        # WAF fronting but let us through (200) — reached, vendor still noted
        (200, "Dashboard", "cloudflare", "reached", "cloudflare"),
        # 503 from a WAF is a block; 503 from a plain server is just an outage → reached
        (503, "", "sucuri", "blocked", "sucuri"),
        (503, "Service Unavailable", "nginx", "reached", None),
    ])
    def test_classification(self, status, title, server, expect_reach, expect_vendor):
        reach, vendor = classify(status, title, server)
        assert reach == expect_reach
        assert vendor == expect_vendor

    def test_none_status_is_reached(self):
        assert classify(None, "", "")[0] == "reached"


class TestFingerprint:
    def test_server_wins(self):
        assert fingerprint_vendor("", "cloudflare-nginx") == "cloudflare"

    def test_title_fallback(self):
        assert fingerprint_vendor("Incapsula incident ID", "") == "imperva"

    def test_no_signal(self):
        assert fingerprint_vendor("Home", "nginx") is None


@pytest.mark.django_db
class TestAnalyzerSetsReachability:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_reachability_persisted(self):
        from apps.httpx.analyzer import analyze
        sess = self._session()
        records = [
            {"url": "https://blocked.example.com:443", "host": "blocked.example.com",
             "port": "443", "scheme": "https", "status_code": 403, "webserver": "cloudflare"},
            {"url": "https://ok.example.com:443", "host": "ok.example.com",
             "port": "443", "scheme": "https", "status_code": 200, "webserver": "nginx"},
        ]
        objs = analyze(sess, records)
        by_host = {o.host: o.reachability for o in objs}
        assert by_host["blocked.example.com"] == "blocked"
        assert by_host["ok.example.com"] == "reached"
