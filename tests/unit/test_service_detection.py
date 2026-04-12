"""Unit tests for apps/core/service_detection — HTTP probes + nmap -sV fallback."""

from unittest.mock import patch, MagicMock
from textwrap import dedent

import pytest
import requests

from apps.core.service_detection.detector import (
    _probe_http, _parse_nmap_sv_xml, _nmap_sv, detect_services, WEB_SERVICES,
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
# WEB_SERVICES constant
# ---------------------------------------------------------------------------

class TestWebServices:
    def test_http_is_web(self):
        assert "http" in WEB_SERVICES

    def test_https_is_web(self):
        assert "https" in WEB_SERVICES

    def test_ssh_is_not_web(self):
        assert "ssh" not in WEB_SERVICES


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

    def test_https_port_classified_as_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_http, \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            mock_http.side_effect = lambda host, port, scheme: scheme == "https" and port == 443
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.is_web is True
        assert p443.service == "https"

    def test_http_port_classified_as_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_http, \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            mock_http.side_effect = lambda host, port, scheme: port == 80 and scheme == "http"
            detect_services(sess)

        p80 = Port.objects.get(session=sess, port=80)
        assert p80.is_web is True
        assert p80.service == "http"

    def test_ssh_port_classified_as_non_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={22: "ssh"}):
            detect_services(sess)

        p22 = Port.objects.get(session=sess, port=22)
        assert p22.is_web is False
        assert p22.service == "ssh"

    def test_nmap_fallback_classifies_https(self):
        """When HTTP probes fail, nmap -sV should detect https and mark is_web=True."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={443: "https", 22: "ssh", 80: "http"}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=443).is_web is True
        assert Port.objects.get(session=sess, port=443).service == "https"
        assert Port.objects.get(session=sess, port=80).is_web is True
        assert Port.objects.get(session=sess, port=22).is_web is False

    def test_nmap_fallback_ssl_tunnel(self):
        """nmap tunnel=ssl + name=http is normalised to ssl/http and treated as web."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={443: "ssl/http"}):  # as normalised by _parse_nmap_sv_xml
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.is_web is True
        assert p443.service == "ssl/http"

    def test_nmap_fallback_unknown_service_stays_non_web(self):
        """If nmap returns an unknown service, port stays non-web."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={22: "unknown", 80: "unknown", 443: "unknown"}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=443).is_web is False

    def test_nmap_fallback_not_called_when_http_succeeds(self):
        """nmap should not be invoked when HTTP probing resolves all ports."""
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=True), \
             patch("apps.core.service_detection.detector._nmap_sv") as mock_nmap:
            detect_services(sess)

        mock_nmap.assert_not_called()

    def test_returns_count_of_updated_ports(self):
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_http, \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            mock_http.side_effect = lambda host, port, scheme: port in (80, 443)
            count = detect_services(sess)

        assert count == 2

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        assert detect_services(sess) == 0

    def test_ssl_unknown_on_443_treated_as_web(self):
        """ssl/unknown on port 443 (client cert / WAF) should be treated as https/web."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={443: "ssl/unknown", 22: "ssl/unknown"}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=443).is_web is True
        assert Port.objects.get(session=sess, port=443).service == "https"
        assert Port.objects.get(session=sess, port=22).is_web is False  # not a web-only port

    def test_tcpwrapped_on_443_treated_as_web(self):
        """tcpwrapped on port 443 should be treated as https/web (firewall intercept)."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={443: "tcpwrapped", 80: "tcpwrapped", 22: "tcpwrapped"}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=443).is_web is True
        assert Port.objects.get(session=sess, port=443).service == "https"
        assert Port.objects.get(session=sess, port=80).is_web is True
        assert Port.objects.get(session=sess, port=80).service == "http"
        assert Port.objects.get(session=sess, port=22).is_web is False  # not a web-only port

    def test_undetectable_port_stays_non_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=22).is_web is False
        assert Port.objects.get(session=sess, port=22).service == ""
