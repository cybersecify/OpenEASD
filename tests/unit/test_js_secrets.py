"""Unit tests for apps/js_secrets — gitleaks over discovered JavaScript assets.

No real network, no real gitleaks: the HTTP fetch (requests) and the gitleaks
subprocess are both mocked. The gitleaks mock writes a JSON report to the
--report-path the collector chose, so the report parser is exercised for real.
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from apps.js_secrets.collector import collect, _is_js_url


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _session():
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full")


def _fake_response(text: str, status: int = 200):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


def _fake_gitleaks(records: list[dict]):
    """Return a subprocess.run stand-in that writes `records` to the report path."""
    def _run(cmd, **kwargs):
        report_path = cmd[cmd.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        m = MagicMock()
        m.returncode = 1 if records else 0  # gitleaks exits 1 when leaks found
        m.stdout = ""
        m.stderr = ""
        return m
    return _run


# --------------------------------------------------------------------------- #
# _is_js_url
# --------------------------------------------------------------------------- #
class TestIsJsUrl:
    def test_plain_js(self):
        assert _is_js_url("https://example.com/app.js")

    def test_uppercase_extension(self):
        assert _is_js_url("https://example.com/APP.JS")

    def test_ignores_query_string(self):
        assert _is_js_url("https://example.com/bundle.js?v=123")

    def test_non_js_rejected(self):
        assert not _is_js_url("https://example.com/index.html")
        assert not _is_js_url("https://example.com/style.css")

    def test_js_in_query_only_rejected(self):
        # .js appears only in the query, not the path
        assert not _is_js_url("https://example.com/load?file=app.js")


# --------------------------------------------------------------------------- #
# collector
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
class TestJsSecretsCollector:
    def test_returns_empty_when_no_js_urls(self):
        sess = _session()
        with patch("apps.js_secrets.collector.subprocess.run") as run:
            records = collect(sess, ["https://example.com/", "https://example.com/a.css"])
        assert records == []
        run.assert_not_called()

    def test_filters_to_js_and_fetches_only_js(self):
        sess = _session()
        urls = [
            "https://example.com/index.html",
            "https://example.com/app.js",
            "https://example.com/style.css",
            "https://example.com/vendor.js",
        ]
        with patch("apps.js_secrets.collector.requests.get", return_value=_fake_response("var x=1;")) as get, \
             patch("apps.js_secrets.collector.subprocess.run", side_effect=_fake_gitleaks([])):
            collect(sess, urls)
        fetched = [c.args[0] for c in get.call_args_list]
        assert set(fetched) == {"https://example.com/app.js", "https://example.com/vendor.js"}

    def test_caps_number_of_js_files(self):
        sess = _session()
        urls = [f"https://example.com/f{i}.js" for i in range(5)]
        with patch("apps.js_secrets.collector.MAX_JS_FILES", 2), \
             patch("apps.js_secrets.collector.requests.get", return_value=_fake_response("x")) as get, \
             patch("apps.js_secrets.collector.subprocess.run", side_effect=_fake_gitleaks([])):
            collect(sess, urls)
        assert get.call_count == 2

    def test_handles_fetch_errors_gracefully(self):
        import requests
        sess = _session()
        urls = ["https://example.com/bad.js", "https://example.com/good.js"]

        def _get(url, **kwargs):
            if "bad" in url:
                raise requests.RequestException("boom")
            return _fake_response("secret code")

        record = {"RuleID": "generic", "File": "/x/1.js", "Secret": "s", "Match": "m"}
        with patch("apps.js_secrets.collector.requests.get", side_effect=_get), \
             patch("apps.js_secrets.collector.subprocess.run", side_effect=_fake_gitleaks([record])):
            records = collect(sess, urls)
        # The good.js file is index 1 → written as 1.js → record maps to it.
        assert len(records) == 1
        assert records[0]["_source_url"] == "https://example.com/good.js"

    def test_skips_gitleaks_when_nothing_fetched(self):
        import requests
        sess = _session()
        with patch("apps.js_secrets.collector.requests.get",
                   side_effect=requests.RequestException("boom")), \
             patch("apps.js_secrets.collector.subprocess.run") as run:
            records = collect(sess, ["https://example.com/app.js"])
        assert records == []
        run.assert_not_called()

    def test_parses_gitleaks_report_and_tags_source_url(self):
        sess = _session()
        records_in = [
            {"RuleID": "aws-access-token", "File": "/tmp/x/0.js",
             "Secret": "AKIAIOSFODNN7EXAMPLE", "Match": "k = AKIAIOSFODNN7EXAMPLE", "StartLine": 3},
            {"RuleID": "generic-api-key", "File": "/tmp/x/0.js",
             "Secret": "abcd1234", "Match": "key=abcd1234", "StartLine": 9},
        ]
        with patch("apps.js_secrets.collector.requests.get", return_value=_fake_response("code")), \
             patch("apps.js_secrets.collector.subprocess.run", side_effect=_fake_gitleaks(records_in)):
            records = collect(sess, ["https://example.com/app.js"])
        assert len(records) == 2
        assert all(r["_source_url"] == "https://example.com/app.js" for r in records)

    def test_empty_report_returns_empty(self):
        sess = _session()
        with patch("apps.js_secrets.collector.requests.get", return_value=_fake_response("code")), \
             patch("apps.js_secrets.collector.subprocess.run", side_effect=_fake_gitleaks([])):
            records = collect(sess, ["https://example.com/app.js"])
        assert records == []

    def test_raises_on_binary_missing(self):
        from apps.core.workflows.exceptions import ToolBinaryMissing
        sess = _session()
        with patch("apps.js_secrets.collector.requests.get", return_value=_fake_response("code")), \
             patch("apps.js_secrets.collector.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(ToolBinaryMissing):
                collect(sess, ["https://example.com/app.js"])

    def test_raises_on_timeout(self):
        from apps.core.workflows.exceptions import ToolTimeout
        sess = _session()
        with patch("apps.js_secrets.collector.requests.get", return_value=_fake_response("code")), \
             patch("apps.js_secrets.collector.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("gitleaks", 300)):
            with pytest.raises(ToolTimeout):
                collect(sess, ["https://example.com/app.js"])


# --------------------------------------------------------------------------- #
# analyzer
# --------------------------------------------------------------------------- #
from apps.js_secrets.analyzer import analyze, _redact


class TestRedact:
    def test_short_secret_fully_masked(self):
        assert _redact("abcd1234") == "*" * 8
        assert "abcd1234" not in _redact("abcd1234")

    def test_long_secret_partly_masked_never_full(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        out = _redact(secret)
        assert secret not in out
        assert "chars" in out

    def test_empty(self):
        assert _redact("") == ""


@pytest.mark.django_db
class TestJsSecretsAnalyzer:
    def _rec(self, **over):
        base = {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "File": "/tmp/x/0.js",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "const key = \"AKIAIOSFODNN7EXAMPLE\"",
            "StartLine": 12,
            "_source_url": "https://example.com/app.js",
        }
        base.update(over)
        return base

    def test_builds_finding(self):
        sess = _session()
        findings = analyze(sess, [self._rec()])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "js_secrets"
        assert f.check_type == "exposed_secret"
        assert f.severity == "high"
        assert "aws-access-token" in f.title
        assert f.target == "https://example.com/app.js"

    def test_full_secret_never_stored(self):
        sess = _session()
        secret = "AKIAIOSFODNN7EXAMPLE"
        findings = analyze(sess, [self._rec()])
        f = findings[0]
        blob = json.dumps(f.extra) + f.title + f.description + f.remediation + f.target
        assert secret not in blob

    def test_dedupes_by_rule_and_url(self):
        sess = _session()
        findings = analyze(sess, [self._rec(), self._rec()])
        assert len(findings) == 1

    def test_different_rules_not_deduped(self):
        sess = _session()
        findings = analyze(sess, [self._rec(), self._rec(RuleID="generic-api-key", Secret="zzzz9999")])
        assert len(findings) == 2

    def test_links_url_fk_when_known(self):
        from apps.core.web_assets.models import URL
        sess = _session()
        url_row = URL.objects.create(
            session=sess, url="https://example.com/app.js", scheme="https",
            host="example.com", port_number=443, source="katana",
        )
        findings = analyze(sess, [self._rec()])
        assert findings[0].url_id == url_row.id

    def test_no_url_fk_for_unknown(self):
        sess = _session()
        findings = analyze(sess, [self._rec(_source_url="https://example.com/other.js")])
        assert findings[0].url is None

    def test_returns_empty_for_no_records(self):
        sess = _session()
        assert analyze(sess, []) == []


# --------------------------------------------------------------------------- #
# scanner
# --------------------------------------------------------------------------- #
from apps.js_secrets.scanner import run_js_secrets


@pytest.mark.django_db
class TestJsSecretsScanner:
    def test_returns_empty_when_no_urls(self):
        sess = _session()
        with patch("apps.js_secrets.scanner.collect") as mock_collect:
            result = run_js_secrets(sess)
        assert result == []
        mock_collect.assert_not_called()

    def test_passes_urls_to_collector_and_saves_findings(self):
        from apps.core.web_assets.models import URL
        from apps.core.findings.models import Finding
        sess = _session()
        URL.objects.create(
            session=sess, url="https://example.com/app.js", scheme="https",
            host="example.com", port_number=443, source="katana",
        )
        record = {
            "RuleID": "aws-access-token", "File": "/tmp/x/0.js",
            "Secret": "AKIAIOSFODNN7EXAMPLE", "Match": "k=AKIAIOSFODNN7EXAMPLE",
            "StartLine": 1, "_source_url": "https://example.com/app.js",
        }
        captured = {}

        def fake_collect(session, urls):
            captured["urls"] = urls
            return [record]

        with patch("apps.js_secrets.scanner.collect", side_effect=fake_collect):
            result = run_js_secrets(sess)

        assert "https://example.com/app.js" in captured["urls"]
        assert len(result) == 1
        saved = Finding.objects.filter(session=sess, source="js_secrets")
        assert saved.count() == 1
        assert saved.first().check_type == "exposed_secret"
