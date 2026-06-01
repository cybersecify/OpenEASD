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
        assert _run_tool("TOOL_GAU", "example.com") == []

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_nonzero_exit_returns_empty(self, mock_run, _which):
        mock_run.return_value = self._mock_run(returncode=1)
        assert _run_tool("TOOL_GAU", "example.com") == []

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_timeout_returns_empty(self, mock_run, _which):
        mock_run.side_effect = subprocess.TimeoutExpired("gau", 300)
        assert _run_tool("TOOL_GAU", "example.com") == []

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_returns_urls_from_stdout(self, mock_run, _which):
        mock_run.return_value = self._mock_run(
            "https://example.com/admin\nhttps://example.com/login\n"
        )
        result = _run_tool("TOOL_GAU", "example.com")
        assert result == ["https://example.com/admin", "https://example.com/login"]

    @patch("apps.historical_urls.collector.shutil.which", return_value="/usr/bin/gau")
    @patch("apps.historical_urls.collector.subprocess.run")
    def test_skips_blank_lines(self, mock_run, _which):
        mock_run.return_value = self._mock_run(
            "https://example.com/page\n\n\nhttps://example.com/other\n"
        )
        result = _run_tool("TOOL_GAU", "example.com")
        assert len(result) == 2


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
