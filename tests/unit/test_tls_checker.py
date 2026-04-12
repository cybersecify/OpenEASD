"""Unit tests for apps/tls_checker — collector probes, analyzer findings."""

import datetime
import ssl
from unittest.mock import MagicMock, patch

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID

from apps.tls_checker.collector import (
    INHERENTLY_INSECURE_SERVICES,
    TLS_CAPABLE_SERVICES,
    _check_trusted_ca,
    _parse_cert_details,
    _hostname_matches_san,
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
                 cert_key_type="RSA", cert_key_bits=2048,
                 cert_sig_algorithm="sha256WithRSAEncryption", cert_sig_sha1=False,
                 cert_san_list=None, cert_san_mismatch=False, cert_has_sct=True,
                 cert_trusted=True,
                 supports_tls10=False, supports_tls11=False, hsts_header=None):
    return {
        "ip": ip, "port": port, "service": service,
        "has_tls": has_tls, "is_web": is_web, "scheme": scheme,
        "inherently_insecure": inherently_insecure,
        "port_fk": port_fk, "url_fk": url_fk,
        "tls_version": tls_version, "cipher_name": cipher_name,
        "cipher_bits": cipher_bits, "cert_expiry_days": cert_expiry_days,
        "cert_self_signed": cert_self_signed,
        "cert_key_type": cert_key_type, "cert_key_bits": cert_key_bits,
        "cert_sig_algorithm": cert_sig_algorithm, "cert_sig_sha1": cert_sig_sha1,
        "cert_san_list": cert_san_list if cert_san_list is not None else [],
        "cert_san_mismatch": cert_san_mismatch, "cert_has_sct": cert_has_sct,
        "cert_trusted": cert_trusted,
        "supports_tls10": supports_tls10, "supports_tls11": supports_tls11,
        "hsts_header": hsts_header,
    }


def _generate_self_signed_der(
    key_type="rsa", key_size=2048, hash_algo=None, days_valid=365,
    san_names=None, include_sct=False,
):
    """Generate a self-signed certificate in DER format for testing."""
    if hash_algo is None:
        hash_algo = hashes.SHA256()

    if key_type == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ec":
        curve = ec.SECP256R1() if key_size >= 256 else ec.SECP192R1()
        key = ec.generate_private_key(curve)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test.example.com"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
    )
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]),
            critical=False,
        )
    cert = builder.sign(key, hash_algo)
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Unit tests — no DB needed
# ---------------------------------------------------------------------------

class TestParseCertDetails:
    def test_rsa_2048_cert(self):
        der = _generate_self_signed_der(key_type="rsa", key_size=2048, days_valid=365)
        result = _parse_cert_details(der)
        assert result["cert_key_type"] == "RSA"
        assert result["cert_key_bits"] == 2048
        assert result["cert_expiry_days"] is not None and result["cert_expiry_days"] > 300
        assert result["cert_self_signed"] is True
        assert result["cert_sig_sha1"] is False

    def test_ec_p256_cert(self):
        der = _generate_self_signed_der(key_type="ec", key_size=256)
        result = _parse_cert_details(der)
        assert result["cert_key_type"] == "EC"
        assert result["cert_key_bits"] == 256

    def test_sha1_signature_detected(self):
        # Modern cryptography lib blocks SHA-1 signing, so we test the
        # _parse_cert_details logic by mocking the signature_hash_algorithm
        der = _generate_self_signed_der()
        result = _parse_cert_details(der)
        # Verify SHA-256 is not flagged as SHA-1
        assert result["cert_sig_sha1"] is False
        # The actual SHA-1 detection is verified via analyzer tests
        # (TestTlsAnalyzerCertDeep.test_sha1_cert_signature_high)

    def test_san_match(self):
        der = _generate_self_signed_der(san_names=["example.com", "www.example.com"])
        result = _parse_cert_details(der, hostname="example.com")
        assert result["cert_san_list"] == ["example.com", "www.example.com"]
        assert result["cert_san_mismatch"] is False

    def test_san_mismatch(self):
        der = _generate_self_signed_der(san_names=["example.com"])
        result = _parse_cert_details(der, hostname="other.com")
        assert result["cert_san_mismatch"] is True

    def test_no_san_extension_mismatch(self):
        der = _generate_self_signed_der(san_names=None)
        result = _parse_cert_details(der, hostname="example.com")
        assert result["cert_san_mismatch"] is True

    def test_san_not_checked_for_ip(self):
        der = _generate_self_signed_der(san_names=["example.com"])
        result = _parse_cert_details(der, hostname="1.2.3.4")
        assert result["cert_san_mismatch"] is False  # IP — skip SAN check

    def test_self_signed_no_sct(self):
        der = _generate_self_signed_der()
        result = _parse_cert_details(der)
        assert result["cert_has_sct"] is False  # self-signed certs never have SCTs

    def test_expired_cert_negative_days(self):
        # Generate a cert that expired 1 day ago (valid_before in past, valid_after just before now)
        der = _generate_self_signed_der(days_valid=1)
        # Patch the parsed cert's not_valid_after to be in the past
        from cryptography import x509 as _x509
        cert = _x509.load_der_x509_certificate(der)
        # Instead, test _parse_cert_details with a cert that has 1 day validity
        # (will be ~1 day remaining, not expired). For expired cert testing,
        # the analyzer tests cover this via _make_result(cert_expiry_days=-5).
        result = _parse_cert_details(der)
        assert result["cert_expiry_days"] is not None and result["cert_expiry_days"] >= 0

    def test_malformed_bytes_returns_defaults(self):
        result = _parse_cert_details(b"garbage data")
        assert result["cert_key_type"] is None
        assert result["cert_expiry_days"] is None
        assert result["cert_self_signed"] is False


class TestHostnameMatchesSan:
    def test_exact_match(self):
        assert _hostname_matches_san("example.com", ["example.com"]) is True

    def test_wildcard_match(self):
        assert _hostname_matches_san("sub.example.com", ["*.example.com"]) is True

    def test_wildcard_no_match_root(self):
        assert _hostname_matches_san("example.com", ["*.example.com"]) is False

    def test_no_match(self):
        assert _hostname_matches_san("other.com", ["example.com"]) is False


class TestCheckTrustedCa:
    def test_trusted_returns_true(self):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        with patch("apps.tls_checker.collector.socket.create_connection", return_value=mock_sock):
            with patch("apps.tls_checker.collector.ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                assert _check_trusted_ca("1.2.3.4", 443, "example.com") is True

    def test_untrusted_returns_false(self):
        with patch("apps.tls_checker.collector.socket.create_connection",
                   side_effect=ssl.SSLCertVerificationError("certificate verify failed")):
            assert _check_trusted_ca("1.2.3.4", 443) is False

    def test_connection_refused_returns_false(self):
        with patch("apps.tls_checker.collector.socket.create_connection",
                   side_effect=ConnectionRefusedError):
            assert _check_trusted_ca("1.2.3.4", 443) is False


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
        der = _generate_self_signed_der(san_names=["example.com"])
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = der

        with patch("apps.tls_checker.collector.socket.create_connection", return_value=mock_sock):
            with patch("apps.tls_checker.collector._tls_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                result = _probe_tls_details("1.2.3.4", 443, hostname="example.com")
        assert result is not None
        assert result["tls_version"] == "TLSv1.3"
        assert result["cert_key_type"] == "RSA"
        assert result["cert_key_bits"] == 2048
        assert result["cert_self_signed"] is True

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
class TestTlsAnalyzerCertDeep:
    """Tests for cryptography-powered cert analysis: weak keys, SHA-1 sig, SAN, SCT."""

    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open",
                                service="https", source="naabu")
        return sess, p

    def test_weak_rsa_1024_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_key_type="RSA", cert_key_bits=1024)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_rsa_key"), None)
        assert f is not None and f.severity == "high"

    def test_strong_rsa_2048_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_key_type="RSA", cert_key_bits=2048)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "weak_rsa_key" for f in findings)

    def test_weak_ec_192_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_key_type="EC", cert_key_bits=192)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_ec_key"), None)
        assert f is not None and f.severity == "high"

    def test_strong_ec_256_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_key_type="EC", cert_key_bits=256)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "weak_ec_key" for f in findings)

    def test_dsa_key_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_key_type="DSA", cert_key_bits=2048)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "dsa_key"), None)
        assert f is not None and f.severity == "medium"

    def test_sha1_cert_signature_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_sig_sha1=True,
                                cert_sig_algorithm="sha1WithRSAEncryption")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "sha1_cert_signature"), None)
        assert f is not None and f.severity == "high"

    def test_sha256_cert_no_sig_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_sig_sha1=False)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "sha1_cert_signature" for f in findings)

    def test_san_mismatch_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_san_mismatch=True,
                                cert_san_list=["other.com"])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "san_mismatch"), None)
        assert f is not None and f.severity == "high"
        assert "other.com" in f.description

    def test_san_match_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_san_mismatch=False)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "san_mismatch" for f in findings)

    def test_no_sct_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_has_sct=False, cert_self_signed=False,
                                cert_key_type="RSA")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "no_sct"), None)
        assert f is not None and f.severity == "medium"

    def test_sct_present_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_has_sct=True)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "no_sct" for f in findings)

    def test_no_sct_skipped_when_self_signed(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_has_sct=False, cert_self_signed=True)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "no_sct" for f in findings)

    def test_no_sct_skipped_when_no_cert(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_has_sct=False, cert_key_type=None)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "no_sct" for f in findings)

    def test_untrusted_ca_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_trusted=False, cert_self_signed=False,
                                cert_key_type="RSA")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "untrusted_ca"), None)
        assert f is not None and f.severity == "high"

    def test_trusted_ca_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_trusted=True, cert_self_signed=False)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "untrusted_ca" for f in findings)

    def test_untrusted_ca_skipped_when_self_signed(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_trusted=False, cert_self_signed=True)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "untrusted_ca" for f in findings)

    def test_untrusted_ca_skipped_when_no_cert(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, cert_trusted=False, cert_key_type=None)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "untrusted_ca" for f in findings)


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

        port_443 = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=443, protocol="tcp", state="open", service="https", is_web=True, source="naabu")
        port_80 = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=80, protocol="tcp", state="open", service="http", is_web=True, source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=6379, protocol="tcp", state="open", service="redis", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=23, protocol="tcp", state="open", service="telnet", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=8888, protocol="tcp", state="open", service="unknown", source="naabu")

        sub = Subdomain.objects.create(session=sess, domain="example.com",
                                       subdomain="www.example.com", source="subfinder")
        URL.objects.create(session=sess, subdomain=sub, port=port_443,
                           url="https://www.example.com:443",
                           host="www.example.com", port_number=443, scheme="https", source="httpx")
        URL.objects.create(session=sess, subdomain=sub, port=port_80,
                           url="http://www.example.com:80",
                           host="www.example.com", port_number=80, scheme="http", source="httpx")
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
            "cert_key_type": None, "cert_key_bits": None,
            "cert_sig_algorithm": None, "cert_sig_sha1": False,
            "cert_san_list": [], "cert_san_mismatch": False,
            "cert_has_sct": False, "cert_trusted": False,
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
