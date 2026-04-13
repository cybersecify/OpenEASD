"""Unit tests for nuclei_network collector — service-aware tag building."""

import pytest
from unittest.mock import MagicMock, patch
from apps.nuclei_network.collector import _build_tags, collect


def _port(service):
    p = MagicMock()
    p.service = service
    p.address = "1.2.3.4"
    p.port = 6379
    return p


def test_build_tags_redis():
    ports = [_port("redis")]
    tags = _build_tags(ports)
    assert "redis" in tags
    assert "misconfig" in tags
    assert "exposures" in tags
    assert "default-login" in tags
    assert "cves" in tags


def test_build_tags_ftp():
    ports = [_port("ftp")]
    tags = _build_tags(ports)
    assert "ftp" in tags


def test_build_tags_smtp():
    ports = [_port("smtp")]
    tags = _build_tags(ports)
    assert "smtp" in tags


def test_build_tags_smtps():
    ports = [_port("smtps")]
    tags = _build_tags(ports)
    assert "smtp" in tags


def test_build_tags_postgresql():
    ports = [_port("postgresql")]
    tags = _build_tags(ports)
    assert "postgresql" in tags


def test_build_tags_postgres_variant():
    ports = [_port("postgres")]
    tags = _build_tags(ports)
    assert "postgresql" in tags


def test_build_tags_ssh_skipped():
    """ssh is handled by ssh_checker — must not appear in nuclei_network tags."""
    ports = [_port("ssh")]
    tags = _build_tags(ports)
    assert "ssh" not in tags
    assert tags == {"misconfig", "exposures", "default-login", "cves"}


def test_build_tags_unknown_service_uses_baseline():
    """Unknown service should fall back to baseline tags only."""
    ports = [_port("unknown-proto")]
    tags = _build_tags(ports)
    assert tags == {"misconfig", "exposures", "default-login", "cves"}


def test_build_tags_empty_service_uses_baseline():
    ports = [_port("")]
    tags = _build_tags(ports)
    assert tags == {"misconfig", "exposures", "default-login", "cves"}


def test_build_tags_none_service_uses_baseline():
    ports = [_port(None)]
    tags = _build_tags(ports)
    assert tags == {"misconfig", "exposures", "default-login", "cves"}


def test_build_tags_multiple_services():
    ports = [_port("redis"), _port("ftp"), _port("mysql")]
    tags = _build_tags(ports)
    assert "redis" in tags
    assert "ftp" in tags
    assert "mysql" in tags


def test_build_tags_case_insensitive():
    ports = [_port("Redis"), _port("FTP"), _port("SMTP")]
    tags = _build_tags(ports)
    assert "redis" in tags
    assert "ftp" in tags
    assert "smtp" in tags


def test_build_tags_microsoft_ds_maps_to_smb():
    ports = [_port("microsoft-ds")]
    tags = _build_tags(ports)
    assert "smb" in tags


def test_build_tags_mongodb():
    ports = [_port("mongodb")]
    tags = _build_tags(ports)
    assert "mongodb" in tags


def test_build_tags_ldap():
    ports = [_port("ldap")]
    tags = _build_tags(ports)
    assert "ldap" in tags


def test_build_tags_vnc():
    ports = [_port("vnc")]
    tags = _build_tags(ports)
    assert "vnc" in tags


def test_build_tags_rdp():
    ports = [_port("rdp")]
    tags = _build_tags(ports)
    assert "rdp" in tags


def test_build_tags_elasticsearch():
    ports = [_port("elasticsearch")]
    tags = _build_tags(ports)
    assert "elasticsearch" in tags


def test_build_tags_memcached():
    ports = [_port("memcached")]
    tags = _build_tags(ports)
    assert "memcached" in tags


def test_build_tags_smb_primary():
    ports = [_port("smb")]
    tags = _build_tags(ports)
    assert "smb" in tags


def test_build_tags_mssql():
    ports = [_port("mssql")]
    tags = _build_tags(ports)
    assert "mssql" in tags


def test_build_tags_cassandra():
    ports = [_port("cassandra")]
    tags = _build_tags(ports)
    assert "cassandra" in tags


def test_build_tags_rabbitmq():
    ports = [_port("rabbitmq")]
    tags = _build_tags(ports)
    assert "rabbitmq" in tags


def test_build_tags_amqp_maps_to_rabbitmq():
    ports = [_port("amqp")]
    tags = _build_tags(ports)
    assert "rabbitmq" in tags


def test_build_tags_returns_set():
    ports = [_port("redis"), _port("redis")]
    tags = _build_tags(ports)
    assert isinstance(tags, set)


@pytest.fixture
def mock_session():
    s = MagicMock()
    s.id = "test-session-id"
    return s


@patch("apps.nuclei_network.collector.subprocess.run")
@patch("apps.nuclei_network.collector.Port")
def test_collect_builds_correct_command(MockPort, mock_run, mock_session):
    port = MagicMock()
    port.address = "1.2.3.4"
    port.port = 6379
    port.service = "redis"
    MockPort.objects.filter.return_value = [port]

    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

    collect(mock_session)

    cmd = mock_run.call_args[0][0]
    assert "-pt" in cmd
    assert "network,ssl" in cmd
    assert "-tags" in cmd
    tags_val = cmd[cmd.index("-tags") + 1]
    assert "redis" in tags_val
    assert "-severity" in cmd
    sev_val = cmd[cmd.index("-severity") + 1]
    assert "critical" in sev_val
    assert "high" in sev_val
    assert "medium" in sev_val
    assert "low" in sev_val
    assert "info" not in sev_val


@patch("apps.nuclei_network.collector.subprocess.run")
@patch("apps.nuclei_network.collector.Port")
def test_collect_no_ports_returns_empty(MockPort, mock_run, mock_session):
    MockPort.objects.filter.return_value = []
    result = collect(mock_session)
    assert result == []
    mock_run.assert_not_called()
