"""Unit tests for apps/naabu — collector parses JSON, analyzer builds Port linked to IPAddress."""

from unittest.mock import MagicMock, patch

import pytest

from apps.naabu.analyzer import analyze
from apps.naabu.collector import collect
from apps.naabu.scanner import run_naabu


@pytest.mark.django_db
class TestNaabuCollector:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_parses_jsonline_output(self):
        sess = self._session()
        fake = MagicMock()
        fake.stdout = (
            '{"ip":"1.2.3.4","port":80,"protocol":"tcp"}\n'
            '{"ip":"1.2.3.4","port":443,"protocol":"tcp"}\n'
            '{"ip":"5.6.7.8","port":22,"protocol":"tcp"}\n'
        )
        with patch("apps.naabu.collector.subprocess.run", return_value=fake):
            records = collect(sess, ["1.2.3.4", "5.6.7.8"])
        assert len(records) == 3
        assert records[0]["host"] == "1.2.3.4"
        assert records[0]["port"] == 80

    def test_uses_host_field_when_no_ip(self):
        sess = self._session()
        fake = MagicMock()
        fake.stdout = '{"host":"1.2.3.4","port":80,"protocol":"tcp"}\n'
        with patch("apps.naabu.collector.subprocess.run", return_value=fake):
            records = collect(sess, ["1.2.3.4"])
        assert records[0]["host"] == "1.2.3.4"

    def test_returns_empty_for_no_targets(self):
        sess = self._session()
        records = collect(sess, [])
        assert records == []

    def test_returns_empty_on_binary_not_found(self):
        sess = self._session()
        with patch("apps.naabu.collector.subprocess.run", side_effect=FileNotFoundError):
            records = collect(sess, ["1.2.3.4"])
        assert records == []


@pytest.mark.django_db
class TestNaabuAnalyzer:
    def test_builds_port_objects(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")

        records = [
            {"host": "1.2.3.4", "port": 80, "protocol": "tcp"},
            {"host": "1.2.3.4", "port": 443, "protocol": "tcp"},
        ]
        objs = analyze(sess, records)
        assert len(objs) == 2
        assert all(isinstance(o, Port) for o in objs)
        assert all(o.source == "naabu" for o in objs)
        assert all(o.state == "open" for o in objs)

    def test_links_port_to_ip_address(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        records = [{"host": "1.2.3.4", "port": 80, "protocol": "tcp"}]
        objs = analyze(sess, records)
        assert objs[0].ip_address == ip

    def test_dedupes_within_batch(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        records = [
            {"host": "1.2.3.4", "port": 80, "protocol": "tcp"},
            {"host": "1.2.3.4", "port": 80, "protocol": "tcp"},
        ]
        objs = analyze(sess, records)
        assert len(objs) == 1

    def test_handles_ip_with_no_matching_address_record(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        # Port for an IP that has no IPAddress record — should still build, just no FK
        records = [{"host": "9.9.9.9", "port": 80, "protocol": "tcp"}]
        objs = analyze(sess, records)
        assert len(objs) == 1
        assert objs[0].ip_address is None
        assert objs[0].address == "9.9.9.9"


@pytest.mark.django_db
class TestNaabuScanner:
    def test_run_naabu_skips_when_no_ips(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        result = run_naabu(sess)
        assert result == []

    def test_run_naabu_writes_to_shared_port_table(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")

        with patch("apps.naabu.scanner.collect", return_value=[
            {"host": "1.2.3.4", "port": 80, "protocol": "tcp"},
            {"host": "1.2.3.4", "port": 443, "protocol": "tcp"},
        ]):
            saved = run_naabu(sess)

        assert len(saved) == 2
        assert Port.objects.filter(session=sess, source="naabu").count() == 2
