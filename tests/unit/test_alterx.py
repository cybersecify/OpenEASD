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
    def test_timeout_raises(self, mock_run, _which):
        from apps.core.workflows.exceptions import ToolTimeout
        mock_run.side_effect = subprocess.TimeoutExpired("alterx", 300)
        with pytest.raises(ToolTimeout):
            collect(["api.example.com"])

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


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

from apps.alterx.analyzer import analyze


@pytest.mark.django_db
class TestAnalyze:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_empty_input_returns_empty(self):
        sess = self._session()
        assert analyze(sess, []) == []

    def test_invalid_hostname_filtered(self):
        sess = self._session()
        objs = analyze(sess, ["not-a-domain", "also bad!", ""])
        assert objs == []

    def test_valid_permutation_builds_subdomain_object(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        objs = analyze(sess, ["api-dev.example.com"])
        assert len(objs) == 1
        assert isinstance(objs[0], Subdomain)
        assert objs[0].subdomain == "api-dev.example.com"
        assert objs[0].source == "alterx"
        assert objs[0].domain == "example.com"

    def test_deduplicates_within_raw_list(self):
        sess = self._session()
        objs = analyze(sess, ["api-dev.example.com", "api-dev.example.com"])
        assert len(objs) == 1

    def test_deduplicates_against_existing_session_subdomains(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="api-dev.example.com", source="subfinder",
        )
        objs = analyze(sess, ["api-dev.example.com", "api-staging.example.com"])
        assert len(objs) == 1
        assert objs[0].subdomain == "api-staging.example.com"

    def test_lowercases_input(self):
        sess = self._session()
        objs = analyze(sess, ["API-DEV.Example.COM"])
        assert objs[0].subdomain == "api-dev.example.com"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

from apps.alterx.scanner import run_alterx


@pytest.mark.django_db
class TestScanner:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_no_subdomains_returns_empty_without_calling_collect(self):
        sess = self._session()
        with patch("apps.alterx.scanner.collect") as mock_collect:
            result = run_alterx(sess)
        assert result == []
        mock_collect.assert_not_called()

    def test_passes_existing_subdomain_names_to_collect(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="api.example.com", source="subfinder",
        )
        captured = {}

        def fake_collect(subdomains):
            captured["subdomains"] = subdomains
            return []

        with patch("apps.alterx.scanner.collect", side_effect=fake_collect):
            run_alterx(sess)

        assert "api.example.com" in captured["subdomains"]

    def test_saves_permutations_and_returns_them(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="api.example.com", source="subfinder",
        )

        with patch("apps.alterx.scanner.collect", return_value=["api-dev.example.com", "api2.example.com"]):
            result = run_alterx(sess)

        assert Subdomain.objects.filter(session=sess, source="alterx").count() == 2
        assert len(result) == 2

    def test_returns_empty_when_collect_returns_nothing(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="api.example.com", source="subfinder",
        )
        with patch("apps.alterx.scanner.collect", return_value=[]):
            result = run_alterx(sess)
        assert result == []
