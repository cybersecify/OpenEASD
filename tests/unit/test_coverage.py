"""Tests for scan coverage (spec C2): _compute_coverage + report note helper."""

import pytest

from apps.core.reports.views import _coverage_context
from apps.core.scans.pipeline import _compute_coverage


def _url(session, host, reachability, web_server="", title=""):
    from apps.core.web_assets.models import URL
    return URL.objects.create(
        session=session, url=f"https://{host}:443", host=host, port_number=443,
        scheme="https", reachability=reachability, web_server=web_server,
        title=title, source="httpx",
    )


@pytest.mark.django_db
class TestComputeCoverage:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_counts_and_vendor(self):
        s = self._session()
        _url(s, "a.example.com", "blocked", web_server="cloudflare")
        _url(s, "b.example.com", "challenged", title="Just a moment...")
        _url(s, "c.example.com", "reached", web_server="nginx")
        _compute_coverage(s)
        assert s.endpoints_probed == 3
        assert s.endpoints_blocked == 2
        assert s.waf_vendor == "cloudflare"

    def test_clean_scan_no_vendor(self):
        s = self._session()
        _url(s, "a.example.com", "reached", web_server="nginx")
        _compute_coverage(s)
        assert s.endpoints_blocked == 0
        assert s.waf_vendor == ""

    def test_ignores_non_httpx_and_blank(self):
        s = self._session()
        _url(s, "a.example.com", "blocked", web_server="cloudflare")
        # non-httpx URL with no reachability must not count
        from apps.core.web_assets.models import URL
        URL.objects.create(session=s, url="https://k.example.com", host="k.example.com",
                           scheme="https", reachability="", source="katana")
        _compute_coverage(s)
        assert s.endpoints_probed == 1
        assert s.endpoints_blocked == 1


@pytest.mark.django_db
class TestCoverageNote:
    def _session(self, **kw):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", **kw)

    def test_none_when_nothing_blocked(self):
        s = self._session(endpoints_probed=5, endpoints_blocked=0, waf_vendor="")
        assert _coverage_context(s) is None

    def test_note_has_endpoint_count_not_percentage(self):
        s = self._session(endpoints_probed=41, endpoints_blocked=12, waf_vendor="cloudflare")
        ctx = _coverage_context(s)
        assert "12 of 41 probed endpoints" in ctx["note"]
        assert "%" not in ctx["note"]  # Phase 1 never prints a percentage
        assert "fingerprint suggests Cloudflare" in ctx["note"]
        assert "not evidence they are secure" in ctx["note"]

    def test_unidentified_vendor_phrasing(self):
        s = self._session(endpoints_probed=10, endpoints_blocked=3, waf_vendor="unidentified")
        ctx = _coverage_context(s)
        assert "vendor unidentified" in ctx["note"]
