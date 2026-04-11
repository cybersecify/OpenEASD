"""Unit tests for apps/subfinder — collector parses JSON output, analyzer builds shared Subdomain assets."""

from unittest.mock import MagicMock, patch

import pytest

from apps.subfinder.analyzer import analyze
from apps.subfinder.collector import collect
from apps.subfinder.scanner import run_subfinder


@pytest.mark.django_db
class TestSubfinderCollector:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_parses_jsonline_output(self):
        sess = self._session()
        fake = MagicMock()
        fake.stdout = (
            '{"host":"api.example.com","ip":"1.2.3.4"}\n'
            '{"host":"www.example.com","ip":"5.6.7.8"}\n'
        )
        with patch("apps.subfinder.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert len(records) == 2
        assert records[0]["host"] == "api.example.com"
        assert records[1]["host"] == "www.example.com"

    def test_handles_missing_ip(self):
        sess = self._session()
        fake = MagicMock()
        fake.stdout = '{"host":"api.example.com"}\n'
        with patch("apps.subfinder.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert records[0]["ip"] is None

    def test_handles_plain_text_fallback(self):
        sess = self._session()
        fake = MagicMock()
        fake.stdout = "api.example.com\nwww.example.com\n"
        with patch("apps.subfinder.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert len(records) == 2

    def test_returns_empty_on_binary_not_found(self):
        sess = self._session()
        with patch("apps.subfinder.collector.subprocess.run", side_effect=FileNotFoundError):
            records = collect(sess)
        assert records == []

    def test_returns_empty_on_timeout(self):
        import subprocess
        sess = self._session()
        with patch("apps.subfinder.collector.subprocess.run", side_effect=subprocess.TimeoutExpired("subfinder", 300)):
            records = collect(sess)
        assert records == []


@pytest.mark.django_db
class TestSubfinderAnalyzer:
    def test_builds_subdomain_objects(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [{"host": "api.example.com"}, {"host": "www.example.com"}]
        objs = analyze(sess, records)
        assert len(objs) == 2
        assert all(isinstance(o, Subdomain) for o in objs)
        assert all(o.source == "subfinder" for o in objs)
        assert all(o.domain == "example.com" for o in objs)

    def test_dedupes_within_batch(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [{"host": "api.example.com"}, {"host": "api.example.com"}]
        objs = analyze(sess, records)
        assert len(objs) == 1

    def test_normalizes_to_lowercase(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [{"host": "API.Example.COM"}]
        objs = analyze(sess, records)
        assert objs[0].subdomain == "api.example.com"

    def test_skips_empty_hosts(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [{"host": ""}, {"host": "  "}, {"host": "valid.example.com"}]
        objs = analyze(sess, records)
        assert len(objs) == 1


@pytest.mark.django_db
class TestSubfinderScanner:
    def test_run_subfinder_writes_to_shared_assets(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        with patch("apps.subfinder.scanner.collect", return_value=[
            {"host": "api.example.com"}, {"host": "www.example.com"}
        ]):
            saved = run_subfinder(sess)
        assert len(saved) == 2
        assert Subdomain.objects.filter(session=sess, source="subfinder").count() == 2
