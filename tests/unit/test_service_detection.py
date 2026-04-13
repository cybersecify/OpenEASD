"""Unit tests for apps/core/service_detection — HTTP probes + nmap -sV fallback."""

from unittest.mock import patch, MagicMock, call
from textwrap import dedent

import pytest
import requests

from apps.core.service_detection.detector import (
    _probe_http, _parse_nmap_sv_xml, _nmap_sv, detect_services,
    WEB_SERVICES, _KNOWN_WEB_PORTS, _grab_banner,
    _banner_score, _nmap_score, _port_hint_score, CLASSIFICATION_THRESHOLD,
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

    # -- Well-known ports: fallback when probing + nmap both fail -----------

    def test_port_443_fallback_when_all_probes_fail(self):
        """Port 443 with no signals scores only port hint (20) — non-web under confidence scoring."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.is_web is False
        assert p443.service == ""

    def test_port_80_fallback_when_all_probes_fail(self):
        """Port 80 with no signals scores only port hint (20) — non-web under confidence scoring."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        p80 = Port.objects.get(session=sess, port=80)
        assert p80.is_web is False
        assert p80.service == ""

    def test_port_443_probe_result_takes_priority_over_fallback(self):
        """If HTTP probe succeeds on 443, use probe result — not fallback."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_probe, \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            mock_probe.side_effect = lambda host, port, scheme: port == 443 and scheme == "https"
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.is_web is True
        assert p443.service == "https"

    # -- Non-standard ports: SSH via nmap -----------------------------------

    def test_ssh_port_classified_as_non_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
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
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
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
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
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
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9999: "unknown"}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=9999).is_web is False

    def test_returns_count_of_updated_ports(self):
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={22: "ssh"}):
            count = detect_services(sess)

        # port 22 → service="ssh" (changed); ports 80 and 443 → no signal, no change
        assert count == 1

    def test_undetectable_non_standard_port_stays_non_web(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9999, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        assert Port.objects.get(session=sess, port=9999).is_web is False
        assert Port.objects.get(session=sess, port=9999).service == ""

    def test_returns_count_of_updated_ports(self):
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={22: "ssh"}):
            count = detect_services(sess)

        # port 22 → service="ssh" (changed); ports 80 and 443 → no signal, no change
        assert count == 1

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        assert detect_services(sess) == 0

    # -- Confidence scoring: tcpwrapped must NOT classify as web --------------

    def test_tcpwrapped_port_9200_is_not_web(self):
        """tcpwrapped contributes 0 — port 9200 stays non-web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9200, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9200: "tcpwrapped"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=9200)
        assert p.is_web is False

    def test_ssl_unknown_on_port_443_is_web(self):
        """ssl/unknown on port 443 scores +40+20=60 >= 50 — classified web (CDN case)."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=443, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={443: "ssl/unknown"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=443)
        assert p.is_web is True

    def test_ssl_unknown_on_port_9200_is_not_web(self):
        """ssl/unknown on non-web port scores +10 < 50 — stays non-web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9200, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9200: "ssl/unknown"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=9200)
        assert p.is_web is False

    def test_ssh_banner_skips_http_probing(self):
        """SSH banner scores -70 — HTTP probing is skipped, port stays non-web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=22, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http") as mock_http, \
             patch("apps.core.service_detection.detector._grab_banner",
                   return_value="SSH-2.0-OpenSSH_8.9\r\n"), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={22: "ssh"}):
            detect_services(sess)
            mock_http.assert_not_called()

        p = Port.objects.get(session=sess, port=22)
        assert p.is_web is False
        assert p.service == "ssh"

    def test_http_probe_success_classifies_as_web(self):
        """HTTP probe success scores +80 >= 50 — classified web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=8888, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http",
                   side_effect=lambda host, port, scheme: scheme == "https"), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=8888)
        assert p.is_web is True
        assert p.service == "https"


# ---------------------------------------------------------------------------
# _grab_banner
# ---------------------------------------------------------------------------

class TestGrabBanner:
    def test_returns_banner_on_successful_connect(self):
        import socket
        from apps.core.service_detection.detector import _grab_banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            result = _grab_banner("1.2.3.4", 22)
        assert result == "SSH-2.0-OpenSSH_8.9\r\n"

    def test_returns_empty_on_connection_refused(self):
        from apps.core.service_detection.detector import _grab_banner
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   side_effect=ConnectionRefusedError()):
            result = _grab_banner("1.2.3.4", 22)
        assert result == ""

    def test_returns_empty_on_timeout(self):
        import socket
        from apps.core.service_detection.detector import _grab_banner
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   side_effect=socket.timeout()):
            result = _grab_banner("1.2.3.4", 9999)
        assert result == ""

    def test_decodes_bytes_ignoring_errors(self):
        from apps.core.service_detection.detector import _grab_banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\xff\xfe HTTP/1.1 200 OK"
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            result = _grab_banner("1.2.3.4", 80)
        assert "HTTP/1.1 200 OK" in result


# ---------------------------------------------------------------------------
# _banner_score
# ---------------------------------------------------------------------------

class TestBannerScore:
    def setup_method(self):
        from apps.core.service_detection.detector import _banner_score
        self.fn = _banner_score

    def test_ssh_banner_negative(self):
        assert self.fn("SSH-2.0-OpenSSH_8.9\r\n") == -70

    def test_ssh1_banner_negative(self):
        assert self.fn("SSH-1.99-OpenSSH_3.9\r\n") == -70

    def test_ftp_banner_negative(self):
        assert self.fn("220 ProFTPD 1.3.5 Server ready\r\n") == -70

    def test_smtp_ehlo_negative(self):
        assert self.fn("EHLO mail.example.com\r\n") == -70

    def test_esmtp_negative(self):
        assert self.fn("220 mail.example.com ESMTP\r\n") == -70

    def test_pop3_ok_greeting_negative(self):
        assert self.fn("+OK POP3 server ready\r\n") == -70

    def test_imap_ok_negative(self):
        assert self.fn("* OK IMAP4rev1 ready\r\n") == -70

    def test_http_response_positive(self):
        assert self.fn("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n") == 70

    def test_html_doctype_positive(self):
        assert self.fn("<!DOCTYPE html><html>") == 70

    def test_html_tag_positive(self):
        assert self.fn("<html lang='en'>") == 70

    def test_empty_banner_zero(self):
        assert self.fn("") == 0

    def test_unknown_banner_zero(self):
        assert self.fn("some random binary garbage \x00\x01\x02") == 0

    def test_web_signal_takes_priority_over_non_web(self):
        # If banner contains both HTTP/ and a non-web signal, web wins (checked first)
        assert self.fn("HTTP/1.1 200 OK\r\n220 ") == 70


# ---------------------------------------------------------------------------
# _nmap_score
# ---------------------------------------------------------------------------

class TestNmapScore:
    def setup_method(self):
        from apps.core.service_detection.detector import _nmap_score
        self.fn = _nmap_score

    def test_http_positive(self):
        assert self.fn("http", 8080) == 70

    def test_https_positive(self):
        assert self.fn("https", 443) == 70

    def test_ssl_http_positive(self):
        assert self.fn("ssl/http", 8443) == 70

    def test_ssl_https_positive(self):
        assert self.fn("ssl/https", 443) == 70

    def test_ssh_negative(self):
        assert self.fn("ssh", 22) == -80

    def test_ftp_negative(self):
        assert self.fn("ftp", 21) == -80

    def test_smtp_negative(self):
        assert self.fn("smtp", 25) == -80

    def test_tcpwrapped_zero(self):
        assert self.fn("tcpwrapped", 443) == 0

    def test_ssl_unknown_on_known_web_port(self):
        assert self.fn("ssl/unknown", 443) == 40

    def test_ssl_unknown_on_known_web_port_8443(self):
        assert self.fn("ssl/unknown", 8443) == 40

    def test_ssl_unknown_on_non_web_port(self):
        assert self.fn("ssl/unknown", 9200) == 10

    def test_empty_string_zero(self):
        assert self.fn("", 1234) == 0

    def test_unknown_service_zero(self):
        assert self.fn("unknown", 9999) == 0


# ---------------------------------------------------------------------------
# _port_hint_score
# ---------------------------------------------------------------------------

class TestPortHintScore:
    def setup_method(self):
        from apps.core.service_detection.detector import _port_hint_score
        self.fn = _port_hint_score

    def test_port_80(self):
        assert self.fn(80) == 20

    def test_port_443(self):
        assert self.fn(443) == 20

    def test_port_8080(self):
        assert self.fn(8080) == 20

    def test_port_8443(self):
        assert self.fn(8443) == 20

    def test_port_22_zero(self):
        assert self.fn(22) == 0

    def test_port_9200_zero(self):
        assert self.fn(9200) == 0
