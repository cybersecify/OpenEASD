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

    def test_raises_on_binary_not_found(self):
        from apps.core.workflows.exceptions import ToolBinaryMissing
        sess = self._session()
        with patch("apps.katana.collector.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(ToolBinaryMissing):
                collect(sess, ["https://example.com"])

    def test_raises_on_timeout(self):
        import subprocess
        from apps.core.workflows.exceptions import ToolTimeout
        sess = self._session()
        with patch("apps.katana.collector.subprocess.run", side_effect=subprocess.TimeoutExpired("katana", 30)):
            with pytest.raises(ToolTimeout):
                collect(sess, ["https://example.com"])

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


from apps.katana.analyzer import analyze


def _make_session_with_assets():
    """Creates session, subdomain, IP, port, and one httpx URL row."""
    from apps.core.scans.models import ScanSession
    from apps.core.assets.models import Subdomain, IPAddress, Port
    from apps.core.web_assets.models import URL

    sess = ScanSession.objects.create(domain="example.com", scan_type="full")
    sub = Subdomain.objects.create(
        session=sess, domain="example.com", subdomain="www.example.com", source="subfinder"
    )
    ip = IPAddress.objects.create(
        session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx"
    )
    port = Port.objects.create(
        session=sess, ip_address=ip, address="1.2.3.4", port=443,
        protocol="tcp", state="open", source="naabu",
    )
    # Seed a httpx URL so the analyzer can look up the port FK
    URL.objects.create(
        session=sess, port=port, subdomain=sub,
        url="https://www.example.com:443", scheme="https",
        host="www.example.com", port_number=443,
        status_code=200, source="httpx",
    )
    return sess, sub, port


@pytest.mark.django_db
class TestKatanaAnalyzer:
    def test_creates_url_row_from_endpoint(self):
        sess, sub, port = _make_session_with_assets()
        records = [{"request": {"endpoint": "https://www.example.com/admin"}}]
        objs = analyze(sess, records)
        assert len(objs) == 1
        assert objs[0].url == "https://www.example.com/admin"
        assert objs[0].source == "katana"

    def test_links_port_fk_via_httpx_url(self):
        sess, sub, port = _make_session_with_assets()
        records = [{"request": {"endpoint": "https://www.example.com/admin"}}]
        objs = analyze(sess, records)
        assert objs[0].port == port

    def test_links_subdomain_fk_via_host(self):
        sess, sub, port = _make_session_with_assets()
        records = [{"request": {"endpoint": "https://www.example.com/dashboard"}}]
        objs = analyze(sess, records)
        assert objs[0].subdomain == sub

    def test_deduplicates_same_url(self):
        sess, _, _ = _make_session_with_assets()
        records = [
            {"request": {"endpoint": "https://www.example.com/page"}},
            {"request": {"endpoint": "https://www.example.com/page"}},
        ]
        objs = analyze(sess, records)
        assert len(objs) == 1

    def test_skips_records_missing_endpoint(self):
        sess, _, _ = _make_session_with_assets()
        records = [{"request": {}}]
        objs = analyze(sess, records)
        assert objs == []

    def test_no_port_fk_for_unknown_host(self):
        sess, _, _ = _make_session_with_assets()
        records = [{"request": {"endpoint": "https://unknown.example.com/page"}}]
        objs = analyze(sess, records)
        assert len(objs) == 1
        assert objs[0].port is None
        assert objs[0].subdomain is None

    def test_sets_scheme_host_port_number(self):
        sess, _, _ = _make_session_with_assets()
        records = [{"request": {"endpoint": "https://www.example.com/path"}}]
        objs = analyze(sess, records)
        assert objs[0].scheme == "https"
        assert objs[0].host == "www.example.com"
        assert objs[0].port_number == 443

    def test_http_default_port_80(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com", subdomain="www.example.com", source="subfinder")
        ip = IPAddress.objects.create(session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4", port=80, protocol="tcp", state="open", source="naabu")
        URL.objects.create(session=sess, port=port, subdomain=sub, url="http://www.example.com:80", scheme="http", host="www.example.com", port_number=80, status_code=200, source="httpx")
        records = [{"request": {"endpoint": "http://www.example.com/path"}}]
        objs = analyze(sess, records)
        assert objs[0].port_number == 80
        assert objs[0].port == port

    def test_returns_empty_for_no_records(self):
        sess, _, _ = _make_session_with_assets()
        assert analyze(sess, []) == []


from apps.katana.scanner import run_katana


@pytest.mark.django_db
class TestKatanaScanner:
    def test_returns_empty_when_no_httpx_urls(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        with patch("apps.katana.scanner.collect") as mock_collect:
            result = run_katana(sess)
        assert result == []
        mock_collect.assert_not_called()

    def test_passes_httpx_urls_to_collector(self):
        sess, sub, port = _make_session_with_assets()  # seeds one httpx URL
        captured = {}

        def fake_collect(session, urls):
            captured["urls"] = urls
            return []

        with patch("apps.katana.scanner.collect", side_effect=fake_collect):
            run_katana(sess)

        assert "https://www.example.com:443" in captured["urls"]

    def test_saves_url_rows_to_db(self):
        from apps.core.web_assets.models import URL
        sess, sub, port = _make_session_with_assets()

        fake_records = [{"request": {"endpoint": "https://www.example.com/admin"}}]

        with patch("apps.katana.scanner.collect", return_value=fake_records):
            result = run_katana(sess)

        saved = URL.objects.filter(session=sess, source="katana")
        assert saved.count() == 1
        assert saved.first().url == "https://www.example.com/admin"
        assert len(result) == 1
