"""Unit tests for apps/core/service_detection — pure Python probes."""

from unittest.mock import patch, MagicMock

import pytest
import requests

from apps.core.service_detection.detector import (
    _probe_http, _probe_banner, _probe_tls,
    detect_services, WEB_SERVICES,
)


# ---------------------------------------------------------------------------
# Unit tests — no DB needed
# ---------------------------------------------------------------------------

class TestWebServices:
    def test_http_is_web(self):
        assert "http" in WEB_SERVICES

    def test_https_is_web(self):
        assert "https" in WEB_SERVICES

    def test_ssh_is_not_web(self):
        assert "ssh" not in WEB_SERVICES


class TestProbeHttp:
    def test_https_detected(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("apps.core.service_detection.detector.requests.head", return_value=mock_resp):
            assert _probe_http("1.2.3.4", 443) == "https"

    def test_http_detected(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        def side_effect(url, **kwargs):
            if url.startswith("https"):
                raise requests.ConnectionError()
            return mock_resp

        with patch("apps.core.service_detection.detector.requests.head", side_effect=side_effect):
            assert _probe_http("1.2.3.4", 80) == "http"

    def test_non_http_returns_none(self):
        with patch("apps.core.service_detection.detector.requests.head",
                   side_effect=requests.ConnectionError()):
            assert _probe_http("1.2.3.4", 22) is None


class TestProbeBanner:
    def test_ssh_banner(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6p1\r\n"

        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            assert _probe_banner("1.2.3.4", 22) == "ssh"

    def test_smtp_banner(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"220 mail.example.com ESMTP Postfix\r\n"

        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            assert _probe_banner("1.2.3.4", 25) == "smtp"

    def test_pop3_banner(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"+OK POP3 server ready\r\n"

        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            assert _probe_banner("1.2.3.4", 110) == "pop3"

    def test_imap_banner(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"* OK IMAP4rev1 server ready\r\n"

        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            assert _probe_banner("1.2.3.4", 143) == "imap"

    def test_redis_banner(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"-ERR unknown command\r\n"

        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            assert _probe_banner("1.2.3.4", 6379) == "redis"

    def test_unknown_banner_returns_none(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"UNKNOWN PROTOCOL\r\n"

        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            assert _probe_banner("1.2.3.4", 9999) is None

    def test_connection_refused_returns_none(self):
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   side_effect=ConnectionRefusedError):
            assert _probe_banner("1.2.3.4", 9999) is None


class TestProbeTls:
    def test_tls_detected(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_ssock = MagicMock()
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            with patch("apps.core.service_detection.detector.ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                assert _probe_tls("1.2.3.4", 443) is True

    def test_no_tls_returns_false(self):
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   side_effect=ConnectionRefusedError):
            assert _probe_tls("1.2.3.4", 22) is False


# ---------------------------------------------------------------------------
# Detector integration — DB required
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

        with patch("apps.core.service_detection.detector._probe_http") as mock_http, \
             patch("apps.core.service_detection.detector._probe_banner") as mock_banner, \
             patch("apps.core.service_detection.detector._probe_tls", return_value=False):
            mock_http.side_effect = lambda ip, port: "http" if port == 80 else "https" if port == 443 else None
            mock_banner.side_effect = lambda ip, port: "ssh" if port == 22 else "redis" if port == 6379 else None
            count = detect_services(sess)

        assert count == 4
        assert Port.objects.get(session=sess, port=22).service == "ssh"
        assert Port.objects.get(session=sess, port=80).service == "http"
        assert Port.objects.get(session=sess, port=443).service == "https"
        assert Port.objects.get(session=sess, port=6379).service == "redis"

    def test_sets_is_web_for_http(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_http, \
             patch("apps.core.service_detection.detector._probe_banner", return_value=None), \
             patch("apps.core.service_detection.detector._probe_tls", return_value=False):
            mock_http.side_effect = lambda ip, port: "http" if port == 80 else "https" if port == 443 else None
            detect_services(sess)

        assert Port.objects.get(session=sess, port=80).is_web is True
        assert Port.objects.get(session=sess, port=443).is_web is True

    def test_ssh_not_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=None), \
             patch("apps.core.service_detection.detector._probe_banner") as mock_banner, \
             patch("apps.core.service_detection.detector._probe_tls", return_value=False):
            mock_banner.side_effect = lambda ip, port: "ssh" if port == 22 else None
            detect_services(sess)

        assert Port.objects.get(session=sess, port=22).is_web is False

    def test_tls_fallback_sets_https(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=None), \
             patch("apps.core.service_detection.detector._probe_banner", return_value=None), \
             patch("apps.core.service_detection.detector._probe_tls") as mock_tls:
            mock_tls.side_effect = lambda ip, port: port == 443
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.service == "https"
        assert p443.is_web is True

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        assert detect_services(sess) == 0

    def test_undetectable_port_not_updated(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=None), \
             patch("apps.core.service_detection.detector._probe_banner", return_value=None), \
             patch("apps.core.service_detection.detector._probe_tls", return_value=False):
            count = detect_services(sess)

        assert count == 0
        assert Port.objects.get(session=sess, port=22).service == ""
