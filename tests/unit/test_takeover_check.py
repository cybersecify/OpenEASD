"""Unit tests for apps/takeover_check — subzy collector, analyzer, scanner."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from apps.takeover_check.analyzer import (
    _is_vulnerable,
    _service_of,
    _subdomain_of,
    analyze,
)
from apps.takeover_check.collector import collect
from apps.takeover_check.scanner import run_takeover_check


# ---------------------------------------------------------------------------
# Analyzer helpers — no DB needed
# ---------------------------------------------------------------------------

class TestIsVulnerable:
    def test_vulnerable_bool_true(self):
        assert _is_vulnerable({"vulnerable": True})

    def test_vuln_bool_true(self):
        assert _is_vulnerable({"vuln": True})

    def test_vulnerable_string_true(self):
        assert _is_vulnerable({"vulnerable": "true"})

    def test_status_contains_vulnerable(self):
        assert _is_vulnerable({"status": "VULNERABLE"})

    def test_status_mixed_case(self):
        assert _is_vulnerable({"status": "Vuln-confirmed"})

    def test_not_vulnerable_default_false(self):
        assert not _is_vulnerable({"vulnerable": False})

    def test_not_vulnerable_empty(self):
        assert not _is_vulnerable({})

    def test_not_vulnerable_status_clean(self):
        assert not _is_vulnerable({"status": "CLEAN"})


class TestSubdomainOf:
    def test_subdomain_key(self):
        assert _subdomain_of({"subdomain": "foo.example.com"}) == "foo.example.com"

    def test_target_fallback(self):
        assert _subdomain_of({"target": "foo.example.com"}) == "foo.example.com"

    def test_host_fallback(self):
        assert _subdomain_of({"host": "foo.example.com"}) == "foo.example.com"

    def test_url_fallback(self):
        assert _subdomain_of({"url": "foo.example.com"}) == "foo.example.com"

    def test_strips_whitespace(self):
        assert _subdomain_of({"subdomain": "  foo.example.com  "}) == "foo.example.com"

    def test_empty_when_no_known_key(self):
        assert _subdomain_of({"other": "x"}) == ""


class TestServiceOf:
    def test_service_key(self):
        assert _service_of({"service": "GitHub Pages"}) == "GitHub Pages"

    def test_platform_fallback(self):
        assert _service_of({"platform": "Heroku"}) == "Heroku"

    def test_engine_fallback(self):
        assert _service_of({"engine": "S3"}) == "S3"

    def test_unknown_when_missing(self):
        assert _service_of({}) == "unknown"


# ---------------------------------------------------------------------------
# Analyzer — needs DB for Subdomain + Finding
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalyze:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def _subdomain(self, session, name):
        from apps.core.assets.models import Subdomain
        return Subdomain.objects.create(
            session=session, domain="example.com",
            subdomain=name, source="subfinder",
        )

    def test_returns_empty_for_no_records(self):
        sess = self._session()
        assert analyze(sess, []) == []

    def test_skips_non_vulnerable(self):
        sess = self._session()
        records = [{"subdomain": "ok.example.com", "vulnerable": False}]
        assert analyze(sess, records) == []

    def test_creates_finding_for_vulnerable_record(self):
        sess = self._session()
        records = [{
            "subdomain": "blog.example.com",
            "vulnerable": True,
            "service": "Tumblr",
        }]
        findings = analyze(sess, records)
        assert len(findings) == 1
        assert findings[0].source == "takeover_check"
        assert findings[0].check_type == "subdomain_takeover"
        assert findings[0].severity == "high"
        assert "blog.example.com" in findings[0].title
        assert "Tumblr" in findings[0].title

    def test_links_subdomain_fk_when_session_has_match(self):
        sess = self._session()
        sub = self._subdomain(sess, "blog.example.com")
        records = [{"subdomain": "blog.example.com", "vulnerable": True}]
        findings = analyze(sess, records)
        assert findings[0].subdomain_id == sub.id

    def test_no_subdomain_fk_when_session_missing_match(self):
        sess = self._session()
        # Note: no Subdomain row created
        records = [{"subdomain": "blog.example.com", "vulnerable": True}]
        findings = analyze(sess, records)
        assert findings[0].subdomain is None
        # But target field still populated for free-floating findings
        assert findings[0].target == "blog.example.com"

    def test_dedupes_by_subdomain_name(self):
        sess = self._session()
        records = [
            {"subdomain": "blog.example.com", "vulnerable": True, "service": "Tumblr"},
            {"subdomain": "blog.example.com", "vulnerable": True, "service": "Tumblr"},
        ]
        findings = analyze(sess, records)
        assert len(findings) == 1

    def test_extra_contains_raw_record(self):
        sess = self._session()
        records = [{
            "subdomain": "blog.example.com",
            "vulnerable": True,
            "service": "Heroku",
            "cname": "old-app.herokuapp.com",
        }]
        findings = analyze(sess, records)
        assert findings[0].extra["service"] == "Heroku"
        assert findings[0].extra["raw"]["cname"] == "old-app.herokuapp.com"

    def test_skips_records_with_no_subdomain_name(self):
        sess = self._session()
        records = [{"vulnerable": True, "service": "S3"}]  # no subdomain key
        assert analyze(sess, records) == []


# ---------------------------------------------------------------------------
# Collector — mock subprocess
# ---------------------------------------------------------------------------

class TestCollectorEdgeCases:
    def test_empty_input_returns_empty(self):
        assert collect([]) == []

    @patch("apps.takeover_check.collector.shutil.which", return_value=None)
    def test_missing_binary_returns_empty(self, _which):
        assert collect(["foo.example.com"]) == []

    @patch("apps.takeover_check.collector.shutil.which", return_value="/usr/local/bin/subzy")
    @patch("apps.takeover_check.collector.subprocess.run")
    def test_nonzero_exit_returns_empty(self, mock_run, _which):
        mock_run.return_value = MagicMock(returncode=1, stderr="boom")
        assert collect(["foo.example.com"]) == []

    @patch("apps.takeover_check.collector.shutil.which", return_value="/usr/local/bin/subzy")
    @patch("apps.takeover_check.collector.subprocess.run")
    def test_returns_records_when_subzy_writes_json_array(self, mock_run, _which, tmp_path):
        # Simulate subzy: when invoked, write JSON to the --output file path,
        # then exit 0. The collector creates the temp paths itself; the side_effect
        # creates the file at the path subzy was told to write to.
        def fake_run(cmd, **kwargs):
            output_idx = cmd.index("--output") + 1
            output_path = cmd[output_idx]
            with open(output_path, "w") as f:
                json.dump(
                    [{"subdomain": "vuln.example.com", "vulnerable": True, "service": "S3"}],
                    f,
                )
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = fake_run
        records = collect(["vuln.example.com"])
        assert len(records) == 1
        assert records[0]["subdomain"] == "vuln.example.com"

    @patch("apps.takeover_check.collector.shutil.which", return_value="/usr/local/bin/subzy")
    @patch("apps.takeover_check.collector.subprocess.run")
    def test_returns_empty_on_invalid_json_output(self, mock_run, _which):
        def fake_run(cmd, **kwargs):
            output_idx = cmd.index("--output") + 1
            with open(cmd[output_idx], "w") as f:
                f.write("not json{")
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = fake_run
        assert collect(["x.example.com"]) == []

    @patch("apps.takeover_check.collector.shutil.which", return_value="/usr/local/bin/subzy")
    @patch("apps.takeover_check.collector.subprocess.run")
    def test_handles_single_object_output(self, mock_run, _which):
        # subzy may emit a single object instead of an array depending on version
        def fake_run(cmd, **kwargs):
            output_idx = cmd.index("--output") + 1
            with open(cmd[output_idx], "w") as f:
                json.dump({"subdomain": "x.example.com", "vulnerable": True}, f)
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = fake_run
        records = collect(["x.example.com"])
        assert len(records) == 1


# ---------------------------------------------------------------------------
# Scanner — orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_returns_empty_when_session_has_no_subdomains(self):
        sess = self._session()
        with patch("apps.takeover_check.scanner.collect") as c:
            assert run_takeover_check(sess) == []
            c.assert_not_called()

    def test_runs_collect_then_analyze_and_persists(self):
        from apps.core.assets.models import Subdomain
        from apps.core.findings.models import Finding

        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="vuln.example.com", source="subfinder",
        )

        fake_records = [{
            "subdomain": "vuln.example.com",
            "vulnerable": True,
            "service": "GitHub Pages",
        }]

        with patch("apps.takeover_check.scanner.collect", return_value=fake_records):
            saved = run_takeover_check(sess)

        assert len(saved) == 1
        assert saved[0].source == "takeover_check"
        # Verify it's actually in the DB
        assert Finding.objects.filter(
            session=sess, source="takeover_check", severity="high"
        ).count() == 1

    def test_no_findings_when_subzy_returns_nothing(self):
        from apps.core.assets.models import Subdomain

        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="ok.example.com", source="subfinder",
        )

        with patch("apps.takeover_check.scanner.collect", return_value=[]):
            assert run_takeover_check(sess) == []
