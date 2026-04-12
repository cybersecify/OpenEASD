"""Unit tests for apps/core/service_detection — XML parsing, Port enrichment."""

from unittest.mock import patch

import pytest

from apps.core.service_detection.parser import parse_services
from apps.core.service_detection.detector import detect_services, WEB_SERVICES


# ---------------------------------------------------------------------------
# Sample nmap -sV XML
# ---------------------------------------------------------------------------

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis" version="7.2.4"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


# ---------------------------------------------------------------------------
# Parser tests — no DB needed
# ---------------------------------------------------------------------------

class TestParseServices:
    def test_extracts_all_services(self):
        results = parse_services(_SAMPLE_XML)
        assert len(results) == 4
        services = {r["service"] for r in results}
        assert services == {"ssh", "http", "https", "redis"}

    def test_extracts_version(self):
        results = parse_services(_SAMPLE_XML)
        ssh = next(r for r in results if r["service"] == "ssh")
        assert ssh["version"] == "OpenSSH 9.6p1"

    def test_extracts_ip_and_port(self):
        results = parse_services(_SAMPLE_XML)
        http = next(r for r in results if r["service"] == "http")
        assert http["ip"] == "1.2.3.4"
        assert http["port"] == 80

    def test_empty_xml(self):
        assert parse_services("") == []

    def test_invalid_xml(self):
        assert parse_services("not xml") == []

    def test_skips_closed_ports(self):
        xml = """<?xml version="1.0"?>
        <nmaprun><host>
          <address addr="1.2.3.4" addrtype="ipv4"/>
          <ports>
            <port protocol="tcp" portid="22">
              <state state="closed"/>
              <service name="ssh"/>
            </port>
          </ports>
        </host></nmaprun>"""
        assert parse_services(xml) == []


class TestWebServices:
    def test_http_is_web(self):
        assert "http" in WEB_SERVICES

    def test_https_is_web(self):
        assert "https" in WEB_SERVICES

    def test_ssh_is_not_web(self):
        assert "ssh" not in WEB_SERVICES


# ---------------------------------------------------------------------------
# Detector tests — DB required
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDetectServices:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=22, protocol="tcp", state="open", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=80, protocol="tcp", state="open", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=443, protocol="tcp", state="open", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=6379, protocol="tcp", state="open", source="naabu")
        return sess

    def test_updates_port_service(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._run_nmap_sv", return_value=_SAMPLE_XML):
            count = detect_services(sess)

        assert count == 4
        ssh_port = Port.objects.get(session=sess, port=22)
        assert ssh_port.service == "ssh"
        assert "OpenSSH" in ssh_port.version

    def test_sets_is_web_for_http(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._run_nmap_sv", return_value=_SAMPLE_XML):
            detect_services(sess)

        http_port = Port.objects.get(session=sess, port=80)
        assert http_port.is_web is True
        https_port = Port.objects.get(session=sess, port=443)
        assert https_port.is_web is True

    def test_ssh_not_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._run_nmap_sv", return_value=_SAMPLE_XML):
            detect_services(sess)

        ssh_port = Port.objects.get(session=sess, port=22)
        assert ssh_port.is_web is False

    def test_redis_not_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._run_nmap_sv", return_value=_SAMPLE_XML):
            detect_services(sess)

        redis_port = Port.objects.get(session=sess, port=6379)
        assert redis_port.is_web is False
        assert redis_port.service == "redis"

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        assert detect_services(sess) == 0

    def test_nmap_binary_not_found(self):
        sess = self._make_session()
        with patch("apps.core.service_detection.detector._run_nmap_sv", return_value=""):
            count = detect_services(sess)
        assert count == 0

    def test_returns_count_of_updated_ports(self):
        sess = self._make_session()
        with patch("apps.core.service_detection.detector._run_nmap_sv", return_value=_SAMPLE_XML):
            count = detect_services(sess)
        assert count == 4
