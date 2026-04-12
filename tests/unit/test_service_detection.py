"""Unit tests for apps/core/service_detection — HTTPS + HTTP probes."""

from unittest.mock import patch, MagicMock

import pytest
import requests

from apps.core.service_detection.detector import (
    _probe_http, detect_services, WEB_SERVICES,
)


# ---------------------------------------------------------------------------
# Unit tests — no DB needed
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


class TestWebServices:
    def test_http_is_web(self):
        assert "http" in WEB_SERVICES

    def test_https_is_web(self):
        assert "https" in WEB_SERVICES

    def test_ssh_is_not_web(self):
        assert "ssh" not in WEB_SERVICES


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
        return sess

    def test_https_port_classified_as_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_http:
            mock_http.side_effect = lambda ip, port, scheme: scheme == "https" and port == 443
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.is_web is True
        assert p443.service == "https"

    def test_http_port_classified_as_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_http:
            mock_http.side_effect = lambda ip, port, scheme: port == 80 and scheme == "http"
            detect_services(sess)

        p80 = Port.objects.get(session=sess, port=80)
        assert p80.is_web is True
        assert p80.service == "http"

    def test_ssh_port_classified_as_non_web(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False):
            detect_services(sess)

        p22 = Port.objects.get(session=sess, port=22)
        assert p22.is_web is False
        assert p22.service == ""

    def test_returns_count_of_web_ports(self):
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http") as mock_http:
            mock_http.side_effect = lambda ip, port, scheme: port in (80, 443)
            count = detect_services(sess)

        assert count == 2

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        assert detect_services(sess) == 0

    def test_undetectable_port_not_updated(self):
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False):
            count = detect_services(sess)

        assert count == 0
        assert Port.objects.get(session=sess, port=22).service == ""
