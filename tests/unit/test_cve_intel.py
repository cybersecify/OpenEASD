"""Unit tests for apps/cve_intel — EPSS + CISA KEV enrichment."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from apps.cve_intel.analyzer import build_finding_intel, finding_cves
from apps.cve_intel import collector


# ---------------------------------------------------------------------------
# analyzer.finding_cves
# ---------------------------------------------------------------------------

class TestFindingCves:
    def _f(self, extra):
        return SimpleNamespace(extra=extra)

    def test_nmap_single_cve_string(self):
        assert finding_cves(self._f({"cve": "CVE-2021-1234"})) == {"CVE-2021-1234"}

    def test_nuclei_cve_ids_list(self):
        got = finding_cves(self._f({"cve_ids": ["CVE-2021-1", "CVE-2021-2"]}))
        assert got == {"CVE-2021-1", "CVE-2021-2"}

    def test_both_keys_merge(self):
        got = finding_cves(self._f({"cve": "CVE-1", "cve_ids": ["CVE-2"]}))
        assert got == {"CVE-1", "CVE-2"}

    def test_uppercase_normalized(self):
        assert finding_cves(self._f({"cve": "cve-2021-9"})) == {"CVE-2021-9"}

    def test_none_and_empty(self):
        assert finding_cves(self._f(None)) == set()
        assert finding_cves(self._f({})) == set()
        assert finding_cves(self._f({"cve": ""})) == set()
        assert finding_cves(self._f({"cve_ids": []})) == set()

    def test_ignores_non_string_members(self):
        assert finding_cves(self._f({"cve_ids": ["CVE-1", None, 5]})) == {"CVE-1"}


# ---------------------------------------------------------------------------
# analyzer.build_finding_intel
# ---------------------------------------------------------------------------

class TestBuildFindingIntel:
    def test_empty_cves(self):
        assert build_finding_intel(set(), {}, {}) == {}

    def test_no_intel_returns_empty(self):
        # CVE present but neither EPSS nor KEV knows it -> nothing to write.
        assert build_finding_intel({"CVE-X"}, {}, {}) == {}

    def test_epss_only(self):
        epss = {"CVE-1": {"epss": 0.42, "percentile": 0.9}}
        intel = build_finding_intel({"CVE-1"}, {}, epss)
        assert intel["epss_score"] == 0.42
        assert intel["epss_percentile"] == 0.9
        assert intel["cisa_kev"] is False

    def test_epss_max_across_cves(self):
        epss = {
            "CVE-1": {"epss": 0.10, "percentile": 0.5},
            "CVE-2": {"epss": 0.80, "percentile": 0.99},
        }
        intel = build_finding_intel({"CVE-1", "CVE-2"}, {}, epss)
        assert intel["epss_score"] == 0.80
        assert intel["epss_percentile"] == 0.99

    def test_kev_flag_and_dates(self):
        kev = {"CVE-1": {"date_added": "2022-01-01", "due_date": "2022-01-15"}}
        intel = build_finding_intel({"CVE-1"}, kev, {})
        assert intel["cisa_kev"] is True
        assert intel["kev_cves"][0]["cve"] == "CVE-1"
        assert intel["kev_cves"][0]["date_added"] == "2022-01-01"

    def test_kev_any_of_multiple(self):
        kev = {"CVE-2": {"date_added": "2022-02-02", "due_date": ""}}
        intel = build_finding_intel({"CVE-1", "CVE-2"}, kev, {})
        assert intel["cisa_kev"] is True

    def test_per_cve_detail_map(self):
        epss = {"CVE-1": {"epss": 0.3, "percentile": 0.7}}
        kev = {"CVE-1": {"date_added": "2022-01-01", "due_date": ""}}
        intel = build_finding_intel({"CVE-1"}, kev, epss)
        assert intel["cve_intel"]["CVE-1"]["epss"] == 0.3
        assert intel["cve_intel"]["CVE-1"]["kev"] is True


# ---------------------------------------------------------------------------
# collector.fetch_kev_catalog
# ---------------------------------------------------------------------------

class TestFetchKevCatalog:
    def setup_method(self):
        from django.core.cache import cache
        cache.delete(collector.KEV_CACHE_KEY)

    def test_happy_path_parses_and_caches(self):
        payload = {"vulnerabilities": [
            {"cveID": "CVE-2021-1", "dateAdded": "2022-01-01", "dueDate": "2022-01-15"},
            {"cveID": "cve-2021-2", "dateAdded": "2022-02-01", "dueDate": ""},
        ]}
        resp = MagicMock(); resp.json.return_value = payload; resp.raise_for_status.return_value = None
        with patch.object(collector.requests, "get", return_value=resp) as g:
            cat = collector.fetch_kev_catalog()
            assert cat["CVE-2021-1"]["date_added"] == "2022-01-01"
            assert "CVE-2021-2" in cat  # uppercased
            # second call served from cache — no second HTTP hit
            collector.fetch_kev_catalog()
            assert g.call_count == 1

    def test_network_failure_returns_empty(self):
        with patch.object(collector.requests, "get", side_effect=collector.requests.RequestException("boom")):
            assert collector.fetch_kev_catalog() == {}

    def test_bad_json_returns_empty(self):
        resp = MagicMock(); resp.raise_for_status.return_value = None
        resp.json.side_effect = ValueError("nope")
        with patch.object(collector.requests, "get", return_value=resp):
            assert collector.fetch_kev_catalog() == {}


# ---------------------------------------------------------------------------
# collector.fetch_epss_scores
# ---------------------------------------------------------------------------

class TestFetchEpssScores:
    def test_happy_path(self):
        payload = {"data": [
            {"cve": "CVE-2021-1", "epss": "0.5", "percentile": "0.9"},
            {"cve": "CVE-2021-2", "epss": "0.1", "percentile": "0.2"},
        ]}
        resp = MagicMock(); resp.json.return_value = payload; resp.raise_for_status.return_value = None
        with patch.object(collector.requests, "get", return_value=resp):
            scores = collector.fetch_epss_scores(["CVE-2021-1", "CVE-2021-2"])
        assert scores["CVE-2021-1"] == {"epss": 0.5, "percentile": 0.9}

    def test_empty_input(self):
        assert collector.fetch_epss_scores([]) == {}

    def test_batching(self):
        big = [f"CVE-2021-{i}" for i in range(collector.EPSS_BATCH + 5)]
        resp = MagicMock(); resp.json.return_value = {"data": []}; resp.raise_for_status.return_value = None
        with patch.object(collector.requests, "get", return_value=resp) as g:
            collector.fetch_epss_scores(big)
            assert g.call_count == 2  # split into two batches

    def test_failed_batch_skipped(self):
        with patch.object(collector.requests, "get", side_effect=collector.requests.RequestException("x")):
            assert collector.fetch_epss_scores(["CVE-1"]) == {}


# ---------------------------------------------------------------------------
# scanner.run_cve_intel
# ---------------------------------------------------------------------------

class TestRunCveIntel:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="running")

    def _finding(self, session, **extra):
        from apps.core.findings.models import Finding
        return Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4:443",
            check_type="cve", severity="high", title="t", description="d",
            extra=extra,
        )

    @pytest.mark.django_db
    def test_no_cve_findings_returns_empty(self):
        from apps.cve_intel.scanner import run_cve_intel
        session = self._session()
        self._finding(session)  # no cve
        assert run_cve_intel(session) == []

    @pytest.mark.django_db
    def test_enriches_and_persists(self):
        from apps.cve_intel.scanner import run_cve_intel
        from apps.core.findings.models import Finding
        session = self._session()
        f = self._finding(session, cve="CVE-2021-1")
        kev = {"CVE-2021-1": {"date_added": "2022-01-01", "due_date": "2022-01-15"}}
        epss = {"CVE-2021-1": {"epss": 0.7, "percentile": 0.95}}
        with patch("apps.cve_intel.scanner.fetch_kev_catalog", return_value=kev), \
             patch("apps.cve_intel.scanner.fetch_epss_scores", return_value=epss):
            updated = run_cve_intel(session)
        assert len(updated) == 1
        f.refresh_from_db()
        assert f.extra["epss_score"] == 0.7
        assert f.extra["cisa_kev"] is True
        assert f.extra["kev_cves"][0]["cve"] == "CVE-2021-1"

    @pytest.mark.django_db
    def test_feeds_down_leaves_findings_untouched(self):
        from apps.cve_intel.scanner import run_cve_intel
        session = self._session()
        f = self._finding(session, cve="CVE-2021-1")
        with patch("apps.cve_intel.scanner.fetch_kev_catalog", return_value={}), \
             patch("apps.cve_intel.scanner.fetch_epss_scores", return_value={}):
            assert run_cve_intel(session) == []
        f.refresh_from_db()
        assert "epss_score" not in f.extra
        assert "cisa_kev" not in f.extra

    @pytest.mark.django_db
    def test_nuclei_cve_ids_list_enriched(self):
        from apps.cve_intel.scanner import run_cve_intel
        session = self._session()
        f = self._finding(session, cve_ids=["CVE-2021-1", "CVE-2021-2"])
        epss = {"CVE-2021-2": {"epss": 0.9, "percentile": 0.99}}
        with patch("apps.cve_intel.scanner.fetch_kev_catalog", return_value={}), \
             patch("apps.cve_intel.scanner.fetch_epss_scores", return_value=epss):
            run_cve_intel(session)
        f.refresh_from_db()
        assert f.extra["epss_score"] == 0.9
