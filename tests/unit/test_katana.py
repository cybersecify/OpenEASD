"""Unit tests for apps/katana — collector parses katana JSONL, analyzer builds URL rows."""

import json
from unittest.mock import MagicMock, patch

import pytest

from apps.katana.collector import collect


@pytest.mark.django_db
class TestKatanaCollector:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def _fake_run(self, lines: list[str]):
        m = MagicMock()
        m.returncode = 0
        m.stdout = "\n".join(lines) + "\n"
        m.stderr = ""
        return m

    def test_parses_jsonl_output(self):
        sess = self._session()
        lines = [
            json.dumps({"request": {"endpoint": "https://example.com/admin"}, "response": {"status_code": 200}}),
            json.dumps({"request": {"endpoint": "https://example.com/login"}, "response": {"status_code": 302}}),
        ]
        with patch("apps.katana.collector.subprocess.run", return_value=self._fake_run(lines)):
            records = collect(sess, ["https://example.com"])
        assert len(records) == 2
        assert records[0]["request"]["endpoint"] == "https://example.com/admin"

    def test_returns_empty_for_no_urls(self):
        sess = self._session()
        records = collect(sess, [])
        assert records == []

    def test_returns_empty_on_binary_not_found(self):
        sess = self._session()
        with patch("apps.katana.collector.subprocess.run", side_effect=FileNotFoundError):
            records = collect(sess, ["https://example.com"])
        assert records == []

    def test_returns_empty_on_timeout(self):
        import subprocess
        sess = self._session()
        with patch("apps.katana.collector.subprocess.run", side_effect=subprocess.TimeoutExpired("katana", 30)):
            records = collect(sess, ["https://example.com"])
        assert records == []

    def test_skips_invalid_json_lines(self):
        sess = self._session()
        m = self._fake_run([
            json.dumps({"request": {"endpoint": "https://example.com/ok"}}),
            "this is not json",
        ])
        with patch("apps.katana.collector.subprocess.run", return_value=m):
            records = collect(sess, ["https://example.com"])
        assert len(records) == 1

    def test_passes_stdin_devnull(self):
        """subprocess.DEVNULL must be passed as stdin to prevent silent hangs."""
        import subprocess
        sess = self._session()
        captured = {}
        def fake_run(*args, **kwargs):
            captured["stdin"] = kwargs.get("stdin")
            m = MagicMock()
            m.returncode = 0
            m.stdout = ""
            m.stderr = ""
            return m
        with patch("apps.katana.collector.subprocess.run", side_effect=fake_run):
            collect(sess, ["https://example.com"])
        assert captured["stdin"] == subprocess.DEVNULL
