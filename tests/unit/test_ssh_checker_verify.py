import pytest
from unittest.mock import patch


def _finding(check_type, extra, target="203.0.113.5:22", severity="high", title="SSH weak config"):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession

    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(
        session=s,
        source="ssh_checker",
        check_type=check_type,
        severity=severity,
        title=title,
        target=target,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# weak_ssh_kex / weak_ssh_cipher / weak_ssh_mac (list-of-offered-algorithms family)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_weak_kex_still_offered_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_kex", {"weak_kex": ["diffie-hellman-group1-sha1"]})
    with patch(
        "apps.ssh_checker.verify._probe",
        return_value={
            "weak_kex_accepted": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
        },
    ):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_weak_kex_gone_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_kex", {"weak_kex": ["diffie-hellman-group1-sha1"]})
    with patch("apps.ssh_checker.verify._probe", return_value={"weak_kex_accepted": []}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_weak_cipher_still_offered_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_cipher", {"weak_ciphers": ["arcfour", "3des-cbc"]})
    with patch(
        "apps.ssh_checker.verify._probe",
        return_value={"weak_ciphers_accepted": ["3des-cbc"]},
    ):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_weak_mac_gone_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_mac", {"weak_macs": ["hmac-md5"]})
    with patch("apps.ssh_checker.verify._probe", return_value={"weak_macs_accepted": ["hmac-sha1"]}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_connect_failure_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_kex", {"weak_kex": ["diffie-hellman-group1-sha1"]})
    with patch("apps.ssh_checker.verify._probe", side_effect=OSError("refused")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# sshv1_supported
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_sshv1_still_supported_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("sshv1_supported", {"server_banner": "SSH-1.5-x"}, severity="critical")
    with patch("apps.ssh_checker.verify._probe", return_value={"supports_sshv1": True}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_sshv1_gone_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("sshv1_supported", {"server_banner": "SSH-1.5-x"}, severity="critical")
    with patch("apps.ssh_checker.verify._probe", return_value={"supports_sshv1": False}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# weak_ssh_host_key
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_weak_host_key_dsa_still_in_use_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_host_key", {"host_key_type": "ssh-dss", "host_key_bits": 1024})
    with patch(
        "apps.ssh_checker.verify._probe",
        return_value={"host_key_type": "ssh-dss", "host_key_bits": 1024},
    ):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_weak_host_key_rsa_still_short_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_host_key", {"host_key_type": "ssh-rsa", "host_key_bits": 1024})
    with patch(
        "apps.ssh_checker.verify._probe",
        return_value={"host_key_type": "ssh-rsa", "host_key_bits": 1024},
    ):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_weak_host_key_rotated_to_ed25519_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("weak_ssh_host_key", {"host_key_type": "ssh-rsa", "host_key_bits": 1024})
    with patch(
        "apps.ssh_checker.verify._probe",
        return_value={"host_key_type": "ssh-ed25519", "host_key_bits": 256},
    ):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# ssh_password_auth / ssh_root_login
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_password_auth_still_enabled_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding(
        "ssh_password_auth", {"auth_methods": ["password", "publickey"]}, severity="medium"
    )
    with patch("apps.ssh_checker.verify._probe", return_value={"auth_methods": ["password"]}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_password_auth_disabled_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding(
        "ssh_password_auth", {"auth_methods": ["password", "publickey"]}, severity="medium"
    )
    with patch("apps.ssh_checker.verify._probe", return_value={"auth_methods": ["publickey"]}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_root_login_still_permitted_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("ssh_root_login", {"root_auth_methods": ["publickey"]}, severity="medium")
    with patch(
        "apps.ssh_checker.verify._probe", return_value={"root_auth_methods": ["publickey"]}
    ):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_root_login_disabled_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("ssh_root_login", {"root_auth_methods": ["publickey"]}, severity="medium")
    with patch("apps.ssh_checker.verify._probe", return_value={"root_auth_methods": []}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# unknown check_type
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_unrecognized_check_type_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict

    f = _finding("ssh_something_else", {})
    v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
