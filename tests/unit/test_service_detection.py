"""Unit tests for apps/core/service_detection — HTTP probes + nmap -sV fallback."""

from unittest.mock import patch, MagicMock, call
from textwrap import dedent

import pytest
import requests

from apps.core.service_detection.detector import (
    _probe_http, _parse_nmap_sv_xml, _nmap_sv, detect_services,
    WEB_SERVICES, _KNOWN_WEB_PORTS,
)


# ---------------------------------------------------------------------------
# _probe_http
# ---------------------------------------------------------------------------

class TestProbeHttp:
    def test_http_responds(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("apps.core.service_detection.detector.requests.head",
                   return_value=mock_resp):
            assert _probe_http("1.2.3.4", 80, "http") is True

    def test_http_no_response(self):
        with patch("apps.core.service_detection.detector.requests.head",
                   side_effect=requests.ConnectionError()):
            assert _probe_http("1.2.3.4", 22, "http") is False


# ---------------------------------------------------------------------------
# WEB_SERVICES / _KNOWN_WEB_PORTS
# ---------------------------------------------------------------------------

class TestWebServices:
    def test_http_is_web(self):
        assert "http" in WEB_SERVICES

    def test_https_is_web(self):
        assert "https" in WEB_SERVICES

    def test_ssh_is_not_web(self):
        assert "ssh" not in WEB_SERVICES


class TestKnownWebPorts:
    def test_standard_ports_present(self):
        assert _KNOWN_WEB_PORTS[80]   == "http"
        assert _KNOWN_WEB_PORTS[443]  == "https"
        assert _KNOWN_WEB_PORTS[8080] == "http"
        assert _KNOWN_WEB_PORTS[8443] == "https"

    def test_ssh_not_known_web(self):
        assert 22 not in _KNOWN_WEB_PORTS


# ---------------------------------------------------------------------------
# _parse_nmap_sv_xml
# ---------------------------------------------------------------------------

class TestParseNmapSvXml:
    _NMAP_HTTPS = dedent("""\
        <?xml version="1.0"?>
        <nmaprun>
          <host><ports>
            <port protocol="tcp" portid="443">
              <state state="open"/>
              <service name="https" product="nginx"/>
            </port>
          </ports></host>
        </nmaprun>
    """)

    _NMAP_HTTP_SSL_TUNNEL = dedent("""\
        <?xml version="1.0"?>
        <nmaprun>
          <host><ports>
            <port protocol="tcp" portid="8443">
              <state state="open"/>
              <service name="http" tunnel="ssl" product="Apache"/>
            </port>
          </ports></host>
        </nmaprun>
    """)

    _NMAP_SSH = dedent("""\
        <?xml version="1.0"?>
        <nmaprun>
          <host><ports>
            <port protocol="tcp" portid="22">
              <state state="open"/>
              <service name="ssh" product="OpenSSH"/>
            </port>
          </ports></host>
        </nmaprun>
    """)

    _NMAP_MULTI = dedent("""\
        <?xml version="1.0"?>
        <nmaprun>
          <host><ports>
            <port protocol="tcp" portid="80">
              <state state="open"/>
              <service name="http"/>
            </port>
            <port protocol="tcp" portid="22">
              <state state="open"/>
              <service name="ssh"/>
            </port>
            <port protocol="tcp" portid="443">
              <state state="open"/>
              <service name="https"/>
            </port>
          </ports></host>
        </nmaprun>
    """)

    def test_https_service(self):
        assert _parse_nmap_sv_xml(self._NMAP_HTTPS) == {443: "https"}

    def test_ssl_tunnel_normalised_to_ssl_http(self):
        # tunnel="ssl" + name="http" → "ssl/http" (matches _NMAP_WEB_SERVICES)
        assert _parse_nmap_sv_xml(self._NMAP_HTTP_SSL_TUNNEL) == {8443: "ssl/http"}

    def test_ssh_service(self):
        assert _parse_nmap_sv_xml(self._NMAP_SSH) == {22: "ssh"}

    def test_multiple_ports(self):
        result = _parse_nmap_sv_xml(self._NMAP_MULTI)
        assert result == {80: "http", 22: "ssh", 443: "https"}

    def test_empty_string_returns_empty(self):
        assert _parse_nmap_sv_xml("") == {}

    def test_malformed_xml_returns_empty(self):
        assert _parse_nmap_sv_xml("<bad xml") == {}


# ---------------------------------------------------------------------------
# detect_services (DB required)
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
        return sess

    # -- Well-known ports: classified by port number, no probing at all -----

    def test_port_443_always_web_no_probing(self):
        """Port 443 must be https/web regardless of probe results."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_probe, \
             patch("apps.core.service_detection.detector._nmap_sv") as mock_nmap:
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.is_web is True
        assert p443.service == "https"
        # well-known ports must not be passed to probing or nmap
        for c in mock_probe.call_args_list:
            assert c.args[1] not in _KNOWN_WEB_PORTS
        for c in mock_nmap.call_args_list:
            assert not any(p in _KNOWN_WEB_PORTS for p in c.args[1])

    def test_port_80_always_web_no_probing(self):
        """Port 80 must be http/web regardless of probe results."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http"), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        p80 = Port.objects.get(session=sess, port=80)
        assert p80.is_web is True
        assert p80.service == "http"

    # -- Non-standard ports: SSH via nmap -----------------------------------

    def test_ssh_port_classified_as_non_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={22: "ssh"}):
            detect_services(sess)

        p22 = Port.objects.get(session=sess, port=22)
        assert p22.is_web is False
        assert p22.service == "ssh"

    # -- Non-standard ports: nmap fallback ----------------------------------

    def test_nmap_fallback_non_standard_https(self):
        """nmap should classify non-standard HTTPS ports correctly."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9443, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9443: "https"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=9443)
        assert p.is_web is True
        assert p.service == "https"

    def test_nmap_fallback_ssl_tunnel_non_standard(self):
        """tunnel=ssl + name=http on non-standard port → ssl/http → web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9443, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9443: "ssl/http"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=9443)
        assert p.is_web is True
        assert p.service == "ssl/http"

    def test_nmap_fallback_unknown_stays_non_web(self):
        """Unknown nmap service on non-standard port stays non-web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9999, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9999: "unknown"}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=9999).is_web is False

    def test_nmap_not_called_for_well_known_ports(self):
        """nmap must never be invoked for well-known web ports."""
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}) as mock_nmap:
            detect_services(sess)

        for c in mock_nmap.call_args_list:
            probed = c.args[1]
            assert not any(p in _KNOWN_WEB_PORTS for p in probed)

    def test_undetectable_non_standard_port_stays_non_web(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9999, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=9999).is_web is False
        assert Port.objects.get(session=sess, port=9999).service == ""

    def test_returns_count_of_updated_ports(self):
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={22: "ssh"}):
            count = detect_services(sess)

        # 80→http, 443→https (well-known), 22→ssh (nmap) — all 3 updated
        assert count == 3

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        assert detect_services(sess) == 0
