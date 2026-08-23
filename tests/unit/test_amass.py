"""Unit tests for apps/amass — collector, analyzer, and scanner."""

import subprocess
from unittest.mock import MagicMock, call, patch

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


def _mock_proc(stdout="", stderr="", returncode=0):
    """Return a mock Popen object whose communicate() returns (stdout, stderr)."""
    proc = MagicMock()
    proc.communicate.return_value = (stdout, stderr)
    proc.returncode = returncode
    return proc


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
        proc = _mock_proc(stdout=(
            '{"name":"api.example.com","domain":"example.com"}\n'
            '{"name":"www.example.com","domain":"example.com"}\n'
        ))
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            records = collect(sess)
        assert len(records) == 2
        assert records[0]["host"] == "api.example.com"
        assert records[1]["host"] == "www.example.com"

    def test_parses_host_key_fallback(self):
        sess = _session()
        _config()
        proc = _mock_proc(stdout='{"host":"sub.example.com"}\n')
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            records = collect(sess)
        assert records[0]["host"] == "sub.example.com"

    def test_parses_plain_text_fallback(self):
        sess = _session()
        _config()
        proc = _mock_proc(stdout="api.example.com\nwww.example.com\n")
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            records = collect(sess)
        assert len(records) == 2

    def test_deduplicates_output(self):
        sess = _session()
        _config()
        proc = _mock_proc(stdout=(
            '{"name":"api.example.com"}\n'
            '{"name":"api.example.com"}\n'
        ))
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            records = collect(sess)
        assert len(records) == 1

    def test_normalizes_to_lowercase(self):
        sess = _session()
        _config()
        proc = _mock_proc(stdout='{"name":"API.Example.COM"}\n')
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            records = collect(sess)
        assert records[0]["host"] == "api.example.com"

    def test_raises_on_binary_not_found(self):
        from apps.core.workflows.exceptions import ToolBinaryMissing
        sess = _session()
        _config()
        with patch("apps.amass.collector.subprocess.Popen", side_effect=FileNotFoundError):
            with pytest.raises(ToolBinaryMissing):
                collect(sess)

    def test_timeout_raises_tooltimeout(self):
        """Hanging 30s past amass's own scan_timeout is an abnormal hang, not a
        clean time-boxed finish — it must raise ToolTimeout so the scan is marked
        'partial', not silently present a truncated surface as complete."""
        from apps.core.workflows.exceptions import ToolTimeout
        sess = _session()
        _config()
        proc = MagicMock()
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired("amass", 30),
            ("api.example.com\n", ""),  # partial output after kill
        ]
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            with pytest.raises(ToolTimeout):
                collect(sess)
        proc.kill.assert_called_once()

    def test_tolerates_nonzero_returncode(self):
        sess = _session()
        _config()
        proc = _mock_proc(stdout='{"name":"api.example.com"}\n', stderr="some warning", returncode=1)
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            records = collect(sess)
        assert len(records) == 1

    def test_skips_empty_lines(self):
        sess = _session()
        _config()
        proc = _mock_proc(stdout='\n\n{"name":"api.example.com"}\n\n')
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc):
            records = collect(sess)
        assert len(records) == 1

    def test_writes_temp_config_when_api_key_set(self):
        sess = _session()
        cfg = _config()
        cfg.shodan_key = "testkey123"
        cfg.save()

        proc = _mock_proc()
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc) as mock_popen:
            collect(sess)
        cmd = mock_popen.call_args[0][0]
        assert "-config" in cmd

        cfg.shodan_key = ""
        cfg.save()

    def test_no_temp_config_when_no_api_keys(self):
        sess = _session()
        _config()
        proc = _mock_proc()
        with patch("apps.amass.collector.subprocess.Popen", return_value=proc) as mock_popen:
            collect(sess)
        cmd = mock_popen.call_args[0][0]
        assert "-config" not in cmd

    def test_low_memory_skips_brute_and_caps_dns(self, settings):
        """Low-memory: amass still enumerates but drops the memory-heavy -brute
        wordlist expansion and caps DNS query concurrency, so it completes on a
        ~1 GB host instead of thrashing."""
        settings.LOW_MEMORY = True
        sess = _session()
        cfg = MagicMock()
        cfg.enabled = True
        cfg.scan_timeout = 30
        cfg.wordlist_file.name = "wl.txt"   # a wordlist IS configured…
        cfg.build_datasource_config.return_value = []
        proc = _mock_proc()
        with patch("apps.amass.models.AmassConfig.get", return_value=cfg), \
             patch("apps.amass.collector.subprocess.Popen", return_value=proc) as mock_popen:
            collect(sess)
        cmd = mock_popen.call_args[0][0]
        assert "-brute" not in cmd            # …but brute is skipped in low-memory
        assert "-max-dns-queries" in cmd      # DNS concurrency capped
        assert "enum" in cmd                   # still enumerating (tool works)


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

    def test_drops_out_of_scope_hosts(self):
        """Scope boundary: only the target domain + its subdomains are kept;
        suffix-bypass tricks are rejected."""
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [
            {"host": "api.example.com"},        # in scope
            {"host": "example.com"},            # in scope (apex)
            {"host": "notexample.com"},         # out — suffix bypass
            {"host": "example.com.evil.com"},   # out — prefix trick
            {"host": "other.org"},              # out
        ]
        hosts = {o.subdomain for o in analyze(sess, records)}
        assert hosts == {"api.example.com", "example.com"}

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
