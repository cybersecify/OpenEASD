"""Unit tests for apps/amass — collector, analyzer, and scanner."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from apps.amass.analyzer import analyze
from apps.amass.collector import collect
from apps.amass.scanner import run_amass


def _session():
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full")


def _config(enabled=True, timeout=30):
    from apps.amass.models import AmassConfig
    cfg = AmassConfig.get()
    cfg.enabled = enabled
    cfg.scan_timeout = timeout
    cfg.save()
    return cfg


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAmassCollector:
    def test_returns_empty_when_disabled(self):
        sess = _session()
        _config(enabled=False)
        records = collect(sess)
        assert records == []

    def test_parses_amass_jsonl_output(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = (
            '{"name":"api.example.com","domain":"example.com"}\n'
            '{"name":"www.example.com","domain":"example.com"}\n'
        )
        fake.stderr = ""
        with patch("apps.amass.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert len(records) == 2
        assert records[0]["host"] == "api.example.com"
        assert records[1]["host"] == "www.example.com"

    def test_parses_host_key_fallback(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = '{"host":"sub.example.com"}\n'
        fake.stderr = ""
        with patch("apps.amass.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert records[0]["host"] == "sub.example.com"

    def test_parses_plain_text_fallback(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = "api.example.com\nwww.example.com\n"
        fake.stderr = ""
        with patch("apps.amass.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert len(records) == 2

    def test_deduplicates_output(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = (
            '{"name":"api.example.com"}\n'
            '{"name":"api.example.com"}\n'
        )
        fake.stderr = ""
        with patch("apps.amass.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert len(records) == 1

    def test_normalizes_to_lowercase(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = '{"name":"API.Example.COM"}\n'
        fake.stderr = ""
        with patch("apps.amass.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert records[0]["host"] == "api.example.com"

    def test_raises_on_binary_not_found(self):
        from apps.core.workflows.exceptions import ToolBinaryMissing
        sess = _session()
        _config()
        with patch("apps.amass.collector.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(ToolBinaryMissing):
                collect(sess)

    def test_raises_on_timeout(self):
        from apps.core.workflows.exceptions import ToolTimeout
        sess = _session()
        _config()
        with patch(
            "apps.amass.collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("amass", 30),
        ):
            with pytest.raises(ToolTimeout):
                collect(sess)

    def test_tolerates_nonzero_returncode(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 1
        fake.stdout = '{"name":"api.example.com"}\n'
        fake.stderr = "some warning"
        with patch("apps.amass.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert len(records) == 1

    def test_skips_empty_lines(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = '\n\n{"name":"api.example.com"}\n\n'
        fake.stderr = ""
        with patch("apps.amass.collector.subprocess.run", return_value=fake):
            records = collect(sess)
        assert len(records) == 1

    def test_writes_temp_config_when_api_key_set(self):
        sess = _session()
        cfg = _config()
        cfg.shodan_key = "testkey123"
        cfg.save()

        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = ""
        fake.stderr = ""

        with patch("apps.amass.collector.subprocess.run", return_value=fake) as mock_run:
            collect(sess)
        cmd = mock_run.call_args[0][0]
        assert "-config" in cmd

        # cleanup
        cfg.shodan_key = ""
        cfg.save()

    def test_no_temp_config_when_no_api_keys(self):
        sess = _session()
        _config()
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = ""
        fake.stderr = ""

        with patch("apps.amass.collector.subprocess.run", return_value=fake) as mock_run:
            collect(sess)
        cmd = mock_run.call_args[0][0]
        assert "-config" not in cmd


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAmassAnalyzer:
    def test_builds_subdomain_objects(self):
        from apps.core.assets.models import Subdomain
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [{"host": "api.example.com"}, {"host": "www.example.com"}]
        objs = analyze(sess, records)
        assert len(objs) == 2
        assert all(isinstance(o, Subdomain) for o in objs)
        assert all(o.source == "amass" for o in objs)
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
        objs = analyze(sess, [{"host": "API.Example.COM"}])
        assert objs[0].subdomain == "api.example.com"

    def test_skips_empty_hosts(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        objs = analyze(sess, [{"host": ""}, {"host": "  "}, {"host": "valid.example.com"}])
        assert len(objs) == 1

    def test_returns_empty_for_no_records(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        assert analyze(sess, []) == []


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAmassScanner:
    def test_saves_subdomains_to_db(self):
        from apps.core.assets.models import Subdomain
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        with patch("apps.amass.scanner.collect", return_value=[
            {"host": "api.example.com"},
            {"host": "www.example.com"},
        ]):
            saved = run_amass(sess)
        assert len(saved) == 2
        assert Subdomain.objects.filter(session=sess, source="amass").count() == 2

    def test_returns_empty_when_collector_returns_nothing(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        with patch("apps.amass.scanner.collect", return_value=[]):
            saved = run_amass(sess)
        assert saved == []
