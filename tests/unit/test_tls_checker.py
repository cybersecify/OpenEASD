"""Unit tests for apps/tls_checker — collector probes, analyzer findings."""

from unittest.mock import MagicMock, patch

import pytest

from apps.tls_checker.collector import (
    INHERENTLY_INSECURE_SERVICES,
    TLS_CAPABLE_SERVICES,
    _cert_days_remaining,
    _is_self_signed,
    _probe_tls_details,
    collect,
)
from apps.tls_checker.analyzer import analyze, _check_rsa_key_exchange
from apps.tls_checker.scanner import run_tls_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(port_fk, ip="1.2.3.4", port=443, service="https",
                 has_tls=True, is_web=False, scheme=None,
                 inherently_insecure=False, url_fk=None,
                 tls_version="TLSv1.3", cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
                 cipher_bits=256, cert_expiry_days=365, cert_self_signed=False,
                 supports_tls10=False, supports_tls11=False, hsts_header=None):
    return {
        "ip": ip, "port": port, "service": service,
        "has_tls": has_tls, "is_web": is_web, "scheme": scheme,
        "inherently_insecure": inherently_insecure,
        "port_fk": port_fk, "url_fk": url_fk,
        "tls_version": tls_version, "cipher_name": cipher_name,
        "cipher_bits": cipher_bits, "cert_expiry_days": cert_expiry_days,
        "cert_self_signed": cert_self_signed,
        "supports_tls10": supports_tls10, "supports_tls11": supports_tls11,
        "hsts_header": hsts_header,
    }


# ---------------------------------------------------------------------------
# Unit tests — no DB needed
# ---------------------------------------------------------------------------

class TestCertHelpers:
    def test_cert_days_remaining_future(self):
        cert = {"notAfter": "Jan 01 00:00:00 2099 GMT"}
        days = _cert_days_remaining(cert)
        assert days is not None and days > 10000

    def test_cert_days_remaining_past(self):
        cert = {"notAfter": "Jan 01 00:00:00 2000 GMT"}
        days = _cert_days_remaining(cert)
        assert days is not None and days < 0

    def test_cert_days_remaining_missing(self):
        assert _cert_days_remaining({}) is None

    def test_is_self_signed_true(self):
        cert = {
            "subject": [[("commonName", "example.com")]],
            "issuer":  [[("commonName", "example.com")]],
        }
        assert _is_self_signed(cert) is True

    def test_is_self_signed_false(self):
        cert = {
            "subject": [[("commonName", "example.com")]],
            "issuer":  [[("commonName", "Let's Encrypt")]],
        }
        assert _is_self_signed(cert) is False

    def test_is_self_signed_empty_cert(self):
        assert _is_self_signed({}) is False


class TestCipherChecks:
    def test_rsa_key_exchange_detected(self):
        assert _check_rsa_key_exchange("RSA-AES256-SHA") is True

    def test_ecdhe_rsa_not_flagged(self):
        assert _check_rsa_key_exchange("ECDHE-RSA-AES256-GCM-SHA384") is False

    def test_dhe_rsa_not_flagged(self):
        assert _check_rsa_key_exchange("DHE-RSA-AES256-GCM-SHA384") is False

    def test_empty_cipher_not_flagged(self):
        assert _check_rsa_key_exchange("") is False


class TestProbeTlsDetails:
    def test_returns_dict_on_successful_handshake(self):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = {}

        with patch("apps.tls_checker.collector.socket.create_connection", return_value=mock_sock):
            with patch("apps.tls_checker.collector._tls_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                result = _probe_tls_details("1.2.3.4", 443)
        assert result is not None
        assert result["tls_version"] == "TLSv1.3"

    def test_returns_none_on_connection_refused(self):
        with patch("apps.tls_checker.collector.socket.create_connection", side_effect=ConnectionRefusedError):
            assert _probe_tls_details("1.2.3.4", 9999) is None

    def test_returns_none_on_timeout(self):
        with patch("apps.tls_checker.collector.socket.create_connection", side_effect=TimeoutError):
            assert _probe_tls_details("1.2.3.4", 6379) is None


# ---------------------------------------------------------------------------
# Analyzer — DB required
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestTlsAnalyzerUnencrypted:
    def _make_port(self, service="redis", port_num=6379):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=port_num, protocol="tcp", state="open",
                                service=service, source="naabu")
        return sess, p

    def test_no_tls_creates_critical_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, service="redis", has_tls=False,
                                tls_version="", cipher_name="")]
        findings = analyze(sess, results)
        unencrypted = [f for f in findings if f.check_type == "unencrypted_service"]
        assert len(unencrypted) == 1
        assert unencrypted[0].severity == "critical"
        assert "REDIS" in unencrypted[0].title

    def test_http_web_port_finding(self):
        sess, port_fk = self._make_port("http", 80)
        results = [_make_result(port_fk, port=80, service="http",
                                has_tls=False, is_web=True, scheme="http",
                                tls_version="", cipher_name="")]
        findings = analyze(sess, results)
        f = next(f for f in findings if f.check_type == "unencrypted_service")
        assert "HTTP" in f.title

    def test_inherently_insecure_creates_finding(self):
        sess, port_fk = self._make_port("telnet", 23)
        results = [_make_result(port_fk, port=23, service="telnet",
                                has_tls=False, inherently_insecure=True,
                                tls_version="", cipher_name="")]
        findings = analyze(sess, results)
        f = next(f for f in findings if f.check_type == "unencrypted_service")
        assert "TELNET" in f.title

    def test_https_no_finding(self):
        sess, port_fk = self._make_port("https", 443)
        results = [_make_result(port_fk, port=443, has_tls=True, is_web=True,
                                scheme="https", tls_version="TLSv1.3",
                                cipher_name="ECDHE-RSA-AES256-GCM-SHA384")]
        findings = analyze(sess, results)
        assert not any(f.check_type == "unencrypted_service" for f in findings)


@pytest.mark.django_db
class TestTlsAnalyzerCipherSuites:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open",
                                service="https", source="naabu")
        return sess, p

    def test_rc4_cipher_critical(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="ECDHE-RSA-RC4-SHA")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "rc4_cipher"), None)
        assert f is not None
        assert f.severity == "critical"

    def test_null_cipher_critical(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="RSA-NULL-SHA")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "null_cipher"), None)
        assert f is not None and f.severity == "critical"

    def test_export_cipher_critical(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="EXP-RSA-DES-CBC-SHA")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "export_cipher"), None)
        assert f is not None and f.severity == "critical"

    def test_3des_sweet32_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="ECDHE-RSA-DES-CBC3-SHA")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "sweet32"), None)
        assert f is not None and f.severity == "high"

    def test_cbc_cipher_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="ECDHE-RSA-AES256-CBC-SHA384")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cbc_cipher"), None)
        assert f is not None and f.severity == "medium"

    def test_rsa_kex_no_forward_secrecy_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="RSA-AES256-GCM-SHA384")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "no_forward_secrecy"), None)
        assert f is not None and f.severity == "high"

    def test_blowfish_sweet32_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="BF-CBC")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "sweet32"), None)
        assert f is not None and f.severity == "high"

    def test_sha1_cipher_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="ECDHE-RSA-AES128-SHA")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "sha1_cipher"), None)
        assert f is not None and f.severity == "medium"

    def test_sha256_cipher_not_flagged(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="ECDHE-RSA-AES256-SHA256")]
        findings = analyze(sess, results)
        assert not any(f.check_type == "sha1_cipher" for f in findings)

    def test_good_cipher_no_findings(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
                                tls_version="TLSv1.3")]
        findings = analyze(sess, results)
        cipher_types = {f.check_type for f in findings}
        assert not cipher_types.intersection({
            "rc4_cipher", "null_cipher", "export_cipher", "sweet32",
            "sha1_cipher", "cbc_cipher", "no_forward_secrecy",
        })


@pytest.mark.django_db
class TestTlsAnalyzerProtocolVersions:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open",
                                service="https", source="naabu")
        return sess, p

    def test_tls10_supported_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, supports_tls10=True)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "tls10_supported"), None)
        assert f is not None and f.severity == "high"

    def test_tls11_supported_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, supports_tls11=True)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "tls11_supported"), None)
        assert f is not None and f.severity == "high"

    def test_tls12_only_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, tls_version="TLSv1.2",
                                supports_tls10=False, supports_tls11=False)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "tls13_not_supported"), None)
        assert f is not None and f.severity == "medium"

    def test_tls13_no_version_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, tls_version="TLSv1.3")]
        findings = analyze(sess, results)
        assert not any(f.check_type in ("tls10_supported", "tls11_supported", "tls13_not_supported")
                       for f in findings)


@pytest.mark.django_db
class TestTlsAnalyzerCertificates:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open",
                                service="https", source="naabu")
        return sess, p

    def test_expired_cert_critical(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_expiry_days=-5)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cert_expired"), None)
        assert f is not None and f.severity == "critical"

    def test_expiring_in_10_days_critical(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_expiry_days=10)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cert_expiring_critical"), None)
        assert f is not None and f.severity == "critical"

    def test_expiring_in_30_days_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_expiry_days=25)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cert_expiring_soon"), None)
        assert f is not None and f.severity == "high"

    def test_expiring_in_60_days_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_expiry_days=60)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cert_expiring"), None)
        assert f is not None and f.severity == "medium"

    def test_valid_cert_no_expiry_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_expiry_days=365)]
        findings = analyze(sess, results)
        assert not any(f.check_type.startswith("cert_expir") for f in findings)

    def test_self_signed_cert_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_self_signed=True)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "self_signed_cert"), None)
        assert f is not None and f.severity == "high"

    def test_trusted_ca_cert_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_self_signed=False)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "self_signed_cert" for f in findings)


@pytest.mark.django_db
class TestTlsAnalyzerHsts:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open",
                                service="https", source="naabu")
        return sess, p

    def test_hsts_missing_https_web_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, has_tls=True, is_web=True, scheme="https",
                                hsts_header=None)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "hsts_missing"), None)
        assert f is not None and f.severity == "high"

    def test_hsts_present_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, has_tls=True, is_web=True, scheme="https",
                                hsts_header="max-age=31536000; includeSubDomains; preload")]
        findings = analyze(sess, results)
        assert not any(f.check_type == "hsts_missing" for f in findings)

    def test_hsts_not_checked_for_non_web(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, has_tls=True, is_web=False, hsts_header=None)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "hsts_missing" for f in findings)

    def test_hsts_not_checked_when_no_tls(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, has_tls=False, is_web=True, scheme="http",
                                hsts_header=None, tls_version="", cipher_name="")]
        findings = analyze(sess, results)
        assert not any(f.check_type == "hsts_missing" for f in findings)


# ---------------------------------------------------------------------------
# Collector integration — mocked probes, DB required
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestTlsCollector:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port, URL, Subdomain

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")

        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=443, protocol="tcp", state="open", service="https", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=80, protocol="tcp", state="open", service="http", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=6379, protocol="tcp", state="open", service="redis", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=23, protocol="tcp", state="open", service="telnet", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=8888, protocol="tcp", state="open", service="unknown", source="naabu")

        sub = Subdomain.objects.create(session=sess, domain="example.com",
                                       subdomain="www.example.com", source="subfinder")
        URL.objects.create(session=sess, subdomain=sub, url="https://1.2.3.4:443",
                           host="1.2.3.4", port_number=443, scheme="https", source="httpx")
        URL.objects.create(session=sess, subdomain=sub, url="http://1.2.3.4:80",
                           host="1.2.3.4", port_number=80, scheme="http", source="httpx")
        return sess

    def test_https_web_port_no_probe(self):
        sess = self._make_session()
        with patch("apps.tls_checker.collector._probe_tls") as mock_probe:
            with patch("apps.tls_checker.collector._probe_tls_details", return_value=None):
                with patch("apps.tls_checker.collector._check_legacy_protocol_support", return_value={}):
                    results = collect(sess)
        https_result = next(r for r in results if r["port"] == 443)
        assert https_result["has_tls"] is True
        assert https_result["is_web"] is True
        assert not any(c.args[:2] == ("1.2.3.4", 443) for c in mock_probe.call_args_list)

    def test_http_web_port_has_tls_false(self):
        sess = self._make_session()
        with patch("apps.tls_checker.collector._probe_tls"):
            with patch("apps.tls_checker.collector._probe_tls_details", return_value=None):
                with patch("apps.tls_checker.collector._check_legacy_protocol_support", return_value={}):
                    results = collect(sess)
        http_result = next(r for r in results if r["port"] == 80)
        assert http_result["has_tls"] is False
        assert http_result["is_web"] is True

    def test_telnet_not_probed(self):
        sess = self._make_session()
        with patch("apps.tls_checker.collector._probe_tls") as mock_probe:
            with patch("apps.tls_checker.collector._probe_tls_details", return_value=None):
                with patch("apps.tls_checker.collector._check_legacy_protocol_support", return_value={}):
                    results = collect(sess)
        telnet = next(r for r in results if r["port"] == 23)
        assert telnet["inherently_insecure"] is True
        assert telnet["has_tls"] is False
        assert not any(c.args[:2] == ("1.2.3.4", 23) for c in mock_probe.call_args_list)

    def test_unknown_service_omitted(self):
        sess = self._make_session()
        with patch("apps.tls_checker.collector._probe_tls", return_value=None):
            with patch("apps.tls_checker.collector._probe_tls_details", return_value=None):
                with patch("apps.tls_checker.collector._check_legacy_protocol_support", return_value={}):
                    results = collect(sess)
        assert 8888 not in {r["port"] for r in results}

    def test_redis_probed(self):
        sess = self._make_session()
        fake_details = {"tls_version": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384",
                        "cipher_bits": 256, "cert_expiry_days": 90, "cert_self_signed": False}
        with patch("apps.tls_checker.collector._probe_tls", return_value=fake_details) as mock_probe:
            with patch("apps.tls_checker.collector._check_legacy_protocol_support",
                       return_value={"tls10": False, "tls11": False}):
                results = collect(sess)
        redis = next((r for r in results if r["port"] == 6379), None)
        assert redis is not None
        mock_probe.assert_any_call("1.2.3.4", 6379, "redis")


# ---------------------------------------------------------------------------
# Scanner orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestTlsScanner:
    def test_scanner_creates_findings(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        from apps.core.findings.models import Finding

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        port_fk = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                      port=23, protocol="tcp", state="open",
                                      service="telnet", source="naabu")

        fake_results = [{
            "ip": "1.2.3.4", "port": 23, "service": "telnet",
            "has_tls": False, "is_web": False, "scheme": None,
            "port_fk": port_fk, "url_fk": None, "inherently_insecure": True,
            "tls_version": "", "cipher_name": "", "cipher_bits": 0,
            "cert_expiry_days": None, "cert_self_signed": False,
            "supports_tls10": False, "supports_tls11": False,
        }]
        with patch("apps.tls_checker.scanner.collect", return_value=fake_results):
            findings = run_tls_check(sess)

        assert len(findings) == 1
        assert Finding.objects.filter(session=sess, source="tls_checker").count() == 1

    def test_scanner_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        with patch("apps.tls_checker.scanner.collect", return_value=[]):
            findings = run_tls_check(sess)
        assert findings == []
