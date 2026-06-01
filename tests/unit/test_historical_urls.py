"""Unit tests for apps/historical_urls — collector, analyzer, scanner."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

from apps.historical_urls.collector import collect, _run_tool


class TestRunTool:
    def _mock_run(self, stdout="", returncode=0):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = ""
        return m

    @patch("apps.historical_urls.collector.shutil.which", return_value=None)
    def test_binary_not_found_returns_empty(self, _which):
        assert _run_tool("gau", "example.com") == []

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_nonzero_exit_returns_empty(self, mock_run, _which):
        mock_run.return_value = self._mock_run(returncode=1)
        assert _run_tool("gau", "example.com") == []

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_timeout_returns_empty(self, mock_run, _which):
        mock_run.side_effect = subprocess.TimeoutExpired("gau", 300)
        assert _run_tool("gau", "example.com") == []

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_returns_urls_from_stdout(self, mock_run, _which):
        mock_run.return_value = self._mock_run(
            "https://example.com/admin\nhttps://example.com/login\n"
        )
        result = _run_tool("gau", "example.com")
        assert result == ["https://example.com/admin", "https://example.com/login"]

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_skips_blank_lines(self, mock_run, _which):
        mock_run.return_value = self._mock_run(
            "https://example.com/page\n\n\nhttps://example.com/other\n"
        )
        result = _run_tool("gau", "example.com")
        assert len(result) == 2

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_file_not_found_returns_empty(self, mock_run, _which):
        mock_run.side_effect = FileNotFoundError
        assert _run_tool("gau", "example.com") == []


class TestCollect:
    @patch("apps.historical_urls.collector._run_tool")
    def test_empty_input_returns_empty(self, _mock):
        assert collect([]) == []

    @patch("apps.historical_urls.collector._run_tool")
    def test_combines_gau_and_waybackurls(self, mock_run_tool):
        mock_run_tool.side_effect = [
            ["https://example.com/from-gau"],
            ["https://example.com/from-wb"],
        ]
        result = collect(["example.com"])
        assert "https://example.com/from-gau" in result
        assert "https://example.com/from-wb" in result

    @patch("apps.historical_urls.collector._run_tool")
    def test_deduplicates_across_tools(self, mock_run_tool):
        mock_run_tool.side_effect = [
            ["https://example.com/page"],
            ["https://example.com/page"],
        ]
        result = collect(["example.com"])
        assert result.count("https://example.com/page") == 1

    @patch("apps.historical_urls.collector._run_tool")
    def test_runs_both_tools_per_subdomain(self, mock_run_tool):
        mock_run_tool.return_value = []
        collect(["a.example.com", "b.example.com"])
        assert mock_run_tool.call_count == 4

    @patch("apps.historical_urls.collector._run_tool")
    def test_both_tools_missing_returns_empty(self, mock_run_tool):
        mock_run_tool.return_value = []
        assert collect(["example.com"]) == []


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

from apps.historical_urls.analyzer import analyze, _is_noise


class TestIsNoise:
    def test_png_is_noise(self):
        assert _is_noise("https://example.com/logo.png")

    def test_jpg_is_noise(self):
        assert _is_noise("https://example.com/photo.jpg")

    def test_woff2_is_noise(self):
        assert _is_noise("https://example.com/font.woff2")

    def test_css_is_noise(self):
        assert _is_noise("https://example.com/style.css")

    def test_zip_is_noise(self):
        assert _is_noise("https://example.com/download.zip")

    def test_html_page_not_noise(self):
        assert not _is_noise("https://example.com/admin")

    def test_php_page_not_noise(self):
        assert not _is_noise("https://example.com/index.php")

    def test_api_endpoint_not_noise(self):
        assert not _is_noise("https://example.com/api/v1/users")

    def test_url_with_query_params_not_noise(self):
        assert not _is_noise("https://example.com/search?q=test")

    def test_uppercase_extension_is_noise(self):
        assert _is_noise("https://example.com/IMAGE.PNG")


@pytest.mark.django_db
class TestAnalyze:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def _make_assets(self, session):
        """Create subdomain + IP + port + httpx URL for FK lookup tests."""
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL
        sub = Subdomain.objects.create(
            session=session, domain="example.com",
            subdomain="www.example.com", source="subfinder",
        )
        ip = IPAddress.objects.create(
            session=session, subdomain=sub,
            address="1.2.3.4", version=4, source="dnsx",
        )
        port = Port.objects.create(
            session=session, ip_address=ip,
            address="1.2.3.4", port=443,
            protocol="tcp", state="open", source="naabu",
        )
        URL.objects.create(
            session=session, port=port, subdomain=sub,
            url="https://www.example.com", scheme="https",
            host="www.example.com", port_number=443,
            status_code=200, source="httpx",
        )
        return sub, port

    def test_empty_returns_empty(self):
        sess = self._session()
        assert analyze(sess, []) == []

    def test_filters_noise_urls(self):
        sess = self._session()
        urls = [
            "https://example.com/logo.png",
            "https://example.com/font.woff2",
            "https://example.com/style.css",
        ]
        assert analyze(sess, urls) == []

    def test_passes_valid_url(self):
        sess = self._session()
        objs = analyze(sess, ["https://example.com/admin"])
        assert len(objs) == 1
        assert objs[0].url == "https://example.com/admin"
        assert objs[0].source == "historical_urls"

    def test_deduplicates_same_url(self):
        sess = self._session()
        objs = analyze(sess, [
            "https://example.com/page",
            "https://example.com/page",
        ])
        assert len(objs) == 1

    def test_links_subdomain_fk(self):
        sess = self._session()
        sub, _ = self._make_assets(sess)
        objs = analyze(sess, ["https://www.example.com/dashboard"])
        assert objs[0].subdomain == sub

    def test_links_port_fk_via_httpx_url(self):
        sess = self._session()
        _, port = self._make_assets(sess)
        objs = analyze(sess, ["https://www.example.com/dashboard"])
        assert objs[0].port == port

    def test_no_fk_for_unknown_host(self):
        sess = self._session()
        objs = analyze(sess, ["https://unknown.example.com/page"])
        assert objs[0].port is None
        assert objs[0].subdomain is None

    def test_sets_scheme_host_port_number(self):
        sess = self._session()
        objs = analyze(sess, ["https://example.com/path"])
        assert objs[0].scheme == "https"
        assert objs[0].host == "example.com"
        assert objs[0].port_number == 443

    def test_http_default_port_80(self):
        sess = self._session()
        objs = analyze(sess, ["http://example.com/path"])
        assert objs[0].port_number == 80

    def test_skips_url_without_scheme(self):
        sess = self._session()
        objs = analyze(sess, ["example.com/path"])
        assert objs == []
