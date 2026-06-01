"""Unit tests for apps/alterx — collector, analyzer, scanner."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

from apps.alterx.collector import collect


class TestCollect:
    def _mock_run(self, stdout="", returncode=0):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = ""
        return m

    def test_empty_input_returns_empty(self):
        assert collect([]) == []

    @patch("apps.alterx.collector.shutil.which", return_value=None)
    def test_binary_not_found_returns_empty(self, _which):
        assert collect(["api.example.com"]) == []

    @patch("apps.alterx.collector.shutil.which", return_value="/usr/bin/alterx")
    @patch("apps.alterx.collector.subprocess.run")
    def test_nonzero_exit_returns_empty(self, mock_run, _which):
        mock_run.return_value = self._mock_run(returncode=1)
        assert collect(["api.example.com"]) == []

    @patch("apps.alterx.collector.shutil.which", return_value="/usr/bin/alterx")
    @patch("apps.alterx.collector.subprocess.run")
    def test_timeout_returns_empty(self, mock_run, _which):
        mock_run.side_effect = subprocess.TimeoutExpired("alterx", 300)
        assert collect(["api.example.com"]) == []

    @patch("apps.alterx.collector.shutil.which", return_value="/usr/bin/alterx")
    @patch("apps.alterx.collector.subprocess.run")
    def test_returns_permutations_from_stdout(self, mock_run, _which):
        mock_run.return_value = self._mock_run(
            "api-dev.example.com\napi2.example.com\napi-staging.example.com\n"
        )
        result = collect(["api.example.com"])
        assert result == ["api-dev.example.com", "api2.example.com", "api-staging.example.com"]

    @patch("apps.alterx.collector.shutil.which", return_value="/usr/bin/alterx")
    @patch("apps.alterx.collector.subprocess.run")
    def test_skips_blank_lines(self, mock_run, _which):
        mock_run.return_value = self._mock_run(
            "api-dev.example.com\n\n\napi2.example.com\n"
        )
        result = collect(["api.example.com"])
        assert len(result) == 2

    @patch("apps.alterx.collector.shutil.which", return_value="/usr/bin/alterx")
    @patch("apps.alterx.collector.subprocess.run")
    def test_pipes_subdomains_as_stdin(self, mock_run, _which):
        mock_run.return_value = self._mock_run("")
        collect(["api.example.com", "dev.example.com"])
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["input"] == "api.example.com\ndev.example.com"
