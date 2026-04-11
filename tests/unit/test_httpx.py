"""Unit tests for apps/httpx — collector parses httpx JSON, analyzer links via host_ip + hostname."""

from unittest.mock import MagicMock, patch

import pytest

from apps.httpx.analyzer import analyze
from apps.httpx.collector import collect
from apps.httpx.scanner import run_httpx


@pytest.mark.django_db
class TestHttpxCollector:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_parses_jsonline_output(self):
        sess = self._session()
        fake = MagicMock()
        fake.stdout = (
            '{"url":"http://www.example.com:80","host":"www.example.com","host_ip":"1.2.3.4","port":"80","status_code":200}\n'
            '{"url":"https://www.example.com:443","host":"www.example.com","host_ip":"1.2.3.4","port":"443","status_code":200}\n'
        )
        with patch("apps.httpx.collector.subprocess.run", return_value=fake):
            records = collect(sess, ["www.example.com:80", "www.example.com:443"])
        assert len(records) == 2
        assert records[0]["url"] == "http://www.example.com:80"

    def test_returns_empty_for_no_targets(self):
        sess = self._session()
        records = collect(sess, [])
        assert records == []

    def test_returns_empty_on_binary_not_found(self):
        sess = self._session()
        with patch("apps.httpx.collector.subprocess.run", side_effect=FileNotFoundError):
            records = collect(sess, ["www.example.com:80"])
        assert records == []


@pytest.mark.django_db
class TestHttpxAnalyzer:
    def _setup_session_with_assets(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com", subdomain="www.example.com", source="subfinder")
        ip = IPAddress.objects.create(session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(
            session=sess, ip_address=ip, address="1.2.3.4", port=443,
            protocol="tcp", state="open", source="naabu",
        )
        return sess, sub, ip, port

    def test_links_url_to_port_via_host_ip(self):
        sess, sub, ip, port = self._setup_session_with_assets()
        records = [{
            "url": "https://www.example.com:443",
            "host": "www.example.com",
            "host_ip": "1.2.3.4",
            "port": "443",
            "scheme": "https",
            "status_code": 200,
        }]
        objs = analyze(sess, records)
        assert len(objs) == 1
        assert objs[0].port == port
        assert objs[0].host == "www.example.com"
        assert objs[0].port_number == 443

    def test_links_url_to_subdomain_by_hostname(self):
        sess, sub, ip, port = self._setup_session_with_assets()
        records = [{
            "url": "https://www.example.com:443",
            "host": "www.example.com",
            "host_ip": "1.2.3.4",
            "port": "443",
        }]
        objs = analyze(sess, records)
        assert objs[0].subdomain == sub

    def test_captures_metadata_fields(self):
        sess, _, _, _ = self._setup_session_with_assets()
        records = [{
            "url": "https://www.example.com:443",
            "host": "www.example.com",
            "host_ip": "1.2.3.4",
            "port": "443",
            "status_code": 200,
            "title": "Example Site",
            "webserver": "nginx/1.22",
            "content_length": 1234,
            "scheme": "https",
        }]
        objs = analyze(sess, records)
        f = objs[0]
        assert f.status_code == 200
        assert f.title == "Example Site"
        assert f.web_server == "nginx/1.22"
        assert f.content_length == 1234
        assert f.scheme == "https"

    def test_dedupes_same_url(self):
        sess, _, _, _ = self._setup_session_with_assets()
        records = [
            {"url": "https://www.example.com:443", "host": "www.example.com", "host_ip": "1.2.3.4", "port": "443"},
            {"url": "https://www.example.com:443", "host": "www.example.com", "host_ip": "1.2.3.4", "port": "443"},
        ]
        objs = analyze(sess, records)
        assert len(objs) == 1

    def test_handles_missing_port_record(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [{
            "url": "https://orphan.example.com:443",
            "host": "orphan.example.com",
            "host_ip": "9.9.9.9",
            "port": "443",
        }]
        # No matching Port — URL should still be created but port FK is None
        objs = analyze(sess, records)
        assert len(objs) == 1
        assert objs[0].port is None
        assert objs[0].subdomain is None

    def test_truncates_long_title(self):
        sess, _, _, _ = self._setup_session_with_assets()
        long_title = "x" * 1000
        records = [{
            "url": "https://www.example.com:443",
            "host": "www.example.com",
            "host_ip": "1.2.3.4",
            "port": "443",
            "title": long_title,
        }]
        objs = analyze(sess, records)
        assert len(objs[0].title) <= 500


@pytest.mark.django_db
class TestHttpxScanner:
    def test_run_httpx_uses_subdomain_hostname_in_targets(self):
        """Regression test: httpx must probe via hostname, not raw IP, so CDNs work."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com", subdomain="cdn.example.com", source="subfinder")
        ip = IPAddress.objects.create(session=sess, subdomain=sub, address="104.21.38.252", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="104.21.38.252", port=443, protocol="tcp", state="open", source="naabu")

        captured = {}
        def fake_collect(session, targets):
            captured["targets"] = targets
            return []

        with patch("apps.httpx.scanner.collect", side_effect=fake_collect):
            run_httpx(sess)

        # Must use the hostname, NOT the raw IP
        assert "cdn.example.com:443" in captured["targets"]
        assert "104.21.38.252:443" not in captured["targets"]

    def test_run_httpx_falls_back_to_ip_when_no_subdomain(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Port

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        Port.objects.create(session=sess, ip_address=None, address="9.9.9.9", port=80, protocol="tcp", state="open", source="naabu")

        captured = {}
        def fake_collect(session, targets):
            captured["targets"] = targets
            return []

        with patch("apps.httpx.scanner.collect", side_effect=fake_collect):
            run_httpx(sess)

        assert "9.9.9.9:80" in captured["targets"]
