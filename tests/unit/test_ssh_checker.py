"""Unit tests for apps/ssh_checker — collector probes, analyzer findings."""

from unittest.mock import MagicMock, patch

import paramiko
import pytest

from apps.ssh_checker.collector import (
    WEAK_KEX_ALGORITHMS,
    WEAK_CIPHERS,
    WEAK_MACS,
    _probe_ssh,
    _test_algorithm,
    collect,
)
from apps.ssh_checker.analyzer import analyze
from apps.ssh_checker.scanner import run_ssh_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(port_fk, ip="1.2.3.4", port=22, service="ssh",
                 probe_success=True,
                 server_banner="SSH-2.0-OpenSSH_8.9p1", supports_sshv1=False,
                 host_key_type="ssh-ed25519", host_key_bits=256,
                 negotiated_kex="curve25519-sha256", negotiated_cipher="aes256-gcm",
                 negotiated_mac="", auth_methods=None, root_auth_methods=None,
                 weak_kex_accepted=None, weak_ciphers_accepted=None,
                 weak_macs_accepted=None):
    return {
        "ip": ip, "port": port, "service": service,
        "port_fk": port_fk, "probe_success": probe_success,
        "server_banner": server_banner, "supports_sshv1": supports_sshv1,
        "host_key_type": host_key_type, "host_key_bits": host_key_bits,
        "negotiated_kex": negotiated_kex, "negotiated_cipher": negotiated_cipher,
        "negotiated_mac": negotiated_mac,
        "auth_methods": auth_methods if auth_methods is not None else ["publickey"],
        "root_auth_methods": root_auth_methods if root_auth_methods is not None else [],
        "weak_kex_accepted": weak_kex_accepted or [],
        "weak_ciphers_accepted": weak_ciphers_accepted or [],
        "weak_macs_accepted": weak_macs_accepted or [],
    }


# ---------------------------------------------------------------------------
# Unit tests — no DB needed
# ---------------------------------------------------------------------------

class TestWeakConstants:
    def test_weak_kex_contains_group1(self):
        assert "diffie-hellman-group1-sha1" in WEAK_KEX_ALGORITHMS

    def test_weak_ciphers_contains_3des(self):
        assert "3des-cbc" in WEAK_CIPHERS

    def test_weak_ciphers_contains_arcfour(self):
        assert "arcfour" in WEAK_CIPHERS

    def test_weak_macs_contains_md5(self):
        assert "hmac-md5" in WEAK_MACS

    def test_weak_macs_contains_sha1(self):
        assert "hmac-sha1" in WEAK_MACS


class TestProbeSSH:
    def test_returns_dict_on_success(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1\r\n"

        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-ed25519"
        mock_key.get_bits.return_value = 256

        mock_transport = MagicMock(spec=paramiko.Transport)
        mock_transport.get_remote_server_key.return_value = mock_key
        mock_transport.remote_version = "SSH-2.0-OpenSSH_8.9p1"
        mock_transport.kex_engine = None
        mock_transport.local_cipher = "aes256-gcm@openssh.com"
        mock_transport.local_mac = ""
        mock_transport.auth_none.side_effect = paramiko.BadAuthenticationType(
            "Bad auth type", ["publickey"]
        )

        with patch("apps.ssh_checker.collector.socket.create_connection", return_value=mock_sock):
            with patch("apps.ssh_checker.collector.paramiko.Transport", return_value=mock_transport):
                with patch("apps.ssh_checker.collector._get_security_options_all"):
                    result = _probe_ssh("1.2.3.4", 22)

        assert result is not None
        assert result["host_key_type"] == "ssh-ed25519"
        assert result["host_key_bits"] == 256
        assert result["supports_sshv1"] is False
        assert result["root_auth_methods"] == ["publickey"]

    def test_sshv1_banner_detected(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-1.5-old_server\r\n"

        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-rsa"
        mock_key.get_bits.return_value = 2048

        mock_transport = MagicMock(spec=paramiko.Transport)
        mock_transport.get_remote_server_key.return_value = mock_key
        mock_transport.remote_version = "SSH-1.5-old_server"
        mock_transport.kex_engine = None
        mock_transport.local_cipher = ""
        mock_transport.local_mac = ""
        mock_transport.auth_none.side_effect = paramiko.AuthenticationException()

        with patch("apps.ssh_checker.collector.socket.create_connection", return_value=mock_sock):
            with patch("apps.ssh_checker.collector.paramiko.Transport", return_value=mock_transport):
                with patch("apps.ssh_checker.collector._get_security_options_all"):
                    result = _probe_ssh("1.2.3.4", 22)

        assert result is not None
        assert result["supports_sshv1"] is True

    def test_returns_none_on_connection_refused(self):
        with patch("apps.ssh_checker.collector.socket.create_connection",
                   side_effect=ConnectionRefusedError):
            assert _probe_ssh("1.2.3.4", 22) is None

    def test_returns_none_on_timeout(self):
        with patch("apps.ssh_checker.collector.socket.create_connection",
                   side_effect=TimeoutError):
            assert _probe_ssh("1.2.3.4", 22) is None


class TestTestAlgorithm:
    def test_accepted_algorithm(self):
        mock_sock = MagicMock()
        mock_transport = MagicMock(spec=paramiko.Transport)
        mock_opts = MagicMock()
        mock_transport.get_security_options.return_value = mock_opts

        with patch("apps.ssh_checker.collector.socket.create_connection", return_value=mock_sock):
            with patch("apps.ssh_checker.collector.paramiko.Transport", return_value=mock_transport):
                assert _test_algorithm("1.2.3.4", 22, cipher="3des-cbc") is True

    def test_rejected_algorithm(self):
        with patch("apps.ssh_checker.collector.socket.create_connection",
                   side_effect=Exception("handshake failed")):
            assert _test_algorithm("1.2.3.4", 22, cipher="3des-cbc") is False


# ---------------------------------------------------------------------------
# Analyzer — DB required
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSshAnalyzerSSHv1:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_sshv1_creates_critical_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, supports_sshv1=True)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "sshv1_supported"), None)
        assert f is not None and f.severity == "critical"

    def test_sshv2_only_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, supports_sshv1=False)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "sshv1_supported" for f in findings)


@pytest.mark.django_db
class TestSshAnalyzerHostKey:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_dsa_key_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, host_key_type="ssh-dss", host_key_bits=1024)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_ssh_host_key"), None)
        assert f is not None and f.severity == "high"
        assert "DSA" in f.title

    def test_rsa_1024_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, host_key_type="ssh-rsa", host_key_bits=1024)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_ssh_host_key"), None)
        assert f is not None and f.severity == "high"

    def test_rsa_2048_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, host_key_type="ssh-rsa", host_key_bits=2048)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "weak_ssh_host_key" for f in findings)

    def test_ed25519_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, host_key_type="ssh-ed25519", host_key_bits=256)]
        findings = analyze(sess, results)
        assert not any(f.check_type == "weak_ssh_host_key" for f in findings)


@pytest.mark.django_db
class TestSshAnalyzerKex:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_weak_kex_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, weak_kex_accepted=["diffie-hellman-group1-sha1"])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_ssh_kex"), None)
        assert f is not None and f.severity == "high"

    def test_strong_kex_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, weak_kex_accepted=[])]
        findings = analyze(sess, results)
        assert not any(f.check_type == "weak_ssh_kex" for f in findings)


@pytest.mark.django_db
class TestSshAnalyzerCiphers:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_3des_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, weak_ciphers_accepted=["3des-cbc"])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_ssh_cipher"), None)
        assert f is not None and f.severity == "high"

    def test_arcfour_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, weak_ciphers_accepted=["arcfour"])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_ssh_cipher"), None)
        assert f is not None

    def test_good_cipher_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, weak_ciphers_accepted=[])]
        findings = analyze(sess, results)
        assert not any(f.check_type == "weak_ssh_cipher" for f in findings)


@pytest.mark.django_db
class TestSshAnalyzerMACs:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_hmac_md5_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, weak_macs_accepted=["hmac-md5"])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "weak_ssh_mac"), None)
        assert f is not None and f.severity == "medium"

    def test_good_mac_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, weak_macs_accepted=[])]
        findings = analyze(sess, results)
        assert not any(f.check_type == "weak_ssh_mac" for f in findings)


@pytest.mark.django_db
class TestSshAnalyzerPasswordAuth:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_password_auth_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, auth_methods=["password", "publickey"])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "ssh_password_auth"), None)
        assert f is not None and f.severity == "medium"

    def test_publickey_only_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, auth_methods=["publickey"])]
        findings = analyze(sess, results)
        assert not any(f.check_type == "ssh_password_auth" for f in findings)


@pytest.mark.django_db
class TestSshAnalyzerRootLogin:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_root_login_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, root_auth_methods=["password", "publickey"])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "ssh_root_login"), None)
        assert f is not None and f.severity == "medium"

    def test_root_rejected_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, root_auth_methods=[])]
        findings = analyze(sess, results)
        assert not any(f.check_type == "ssh_root_login" for f in findings)


@pytest.mark.django_db
class TestSshAnalyzerProbeFailure:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=22, protocol="tcp", state="open",
                                service="ssh", source="naabu")
        return sess, p

    def test_failed_probe_no_findings(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk, probe_success=False)]
        findings = analyze(sess, results)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Collector integration — mocked probes, DB required
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSshCollector:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=22, protocol="tcp", state="open", service="ssh", source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=443, protocol="tcp", state="open", service="https", source="naabu")
        return sess

    def test_only_ssh_ports_probed(self):
        sess = self._make_session()
        fake_probe = {
            "server_banner": "SSH-2.0-OpenSSH_8.9p1", "supports_sshv1": False,
            "host_key_type": "ssh-ed25519", "host_key_bits": 256,
            "negotiated_kex": "", "negotiated_cipher": "", "negotiated_mac": "",
            "auth_methods": ["publickey"], "root_auth_methods": [],
        }
        with patch("apps.ssh_checker.collector._probe_ssh", return_value=fake_probe) as mock_probe:
            with patch("apps.ssh_checker.collector._probe_weak_algorithms",
                       return_value={"weak_kex_accepted": [], "weak_ciphers_accepted": [], "weak_macs_accepted": []}):
                results = collect(sess)
        assert len(results) == 1
        assert results[0]["port"] == 22
        mock_probe.assert_called_once_with("1.2.3.4", 22)

    def test_probe_failure_recorded(self):
        sess = self._make_session()
        with patch("apps.ssh_checker.collector._probe_ssh", return_value=None):
            results = collect(sess)
        assert len(results) == 1
        assert results[0]["probe_success"] is False


# ---------------------------------------------------------------------------
# Scanner orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSshScanner:
    def test_scanner_creates_findings(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        from apps.core.findings.models import Finding

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        port_fk = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                      port=22, protocol="tcp", state="open",
                                      service="ssh", source="naabu")

        fake_results = [{
            "ip": "1.2.3.4", "port": 22, "service": "ssh",
            "port_fk": port_fk, "probe_success": True,
            "server_banner": "SSH-2.0-OpenSSH_7.2",
            "supports_sshv1": False,
            "host_key_type": "ssh-dss", "host_key_bits": 1024,
            "negotiated_kex": "", "negotiated_cipher": "", "negotiated_mac": "",
            "auth_methods": ["password", "publickey"],
            "root_auth_methods": ["password", "publickey"],
            "weak_kex_accepted": ["diffie-hellman-group1-sha1"],
            "weak_ciphers_accepted": ["3des-cbc"],
            "weak_macs_accepted": ["hmac-md5"],
        }]
        with patch("apps.ssh_checker.scanner.collect", return_value=fake_results):
            findings = run_ssh_check(sess)

        # Should produce: weak_host_key, weak_kex, weak_cipher, weak_mac, password_auth, root_login
        assert len(findings) >= 5
        assert Finding.objects.filter(session=sess, source="ssh_checker").count() == len(findings)

    def test_scanner_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        with patch("apps.ssh_checker.scanner.collect", return_value=[]):
            findings = run_ssh_check(sess)
        assert findings == []
