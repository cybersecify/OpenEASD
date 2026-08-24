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


def test_build_tags_ms_wbt_server_maps_to_rdp():
    """nmap names RDP as ms-wbt-server — must map to rdp tag."""
    ports = [_port("ms-wbt-server")]
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


def test_build_tags_returns_deduped_set_with_baseline():
    # Two redis ports must collapse to a single "redis" tag, and the baseline
    # tags must always be present alongside it.
    ports = [_port("redis"), _port("redis")]
    tags = _build_tags(ports)
    assert isinstance(tags, set)
    assert tags == {"redis", "misconfig", "exposures", "default-login", "cves"}


@pytest.fixture
def mock_session():
    s = MagicMock()
    s.id = "test-session-id"
    return s


@patch("apps.nuclei_network.collector.run_capped")
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


@patch("apps.nuclei_network.collector.run_capped")
@patch("apps.nuclei_network.collector.Port")
def test_collect_no_ports_returns_empty(MockPort, mock_run, mock_session):
    MockPort.objects.filter.return_value = []
    result = collect(mock_session)
    assert result == []
    mock_run.assert_not_called()


@patch("apps.nuclei_network.collector.run_capped")
@patch("apps.nuclei_network.collector.Port")
def test_collect_binary_missing_raises(MockPort, mock_run, mock_session):
    """A missing nuclei binary must surface as ToolBinaryMissing, not a silent []
    — a false 'completed with 0 findings' hides the broken install."""
    from apps.core.workflows.exceptions import ToolBinaryMissing
    port = MagicMock(address="1.2.3.4", port=6379, service="redis")
    MockPort.objects.filter.return_value = [port]
    mock_run.side_effect = FileNotFoundError()
    with pytest.raises(ToolBinaryMissing):
        collect(mock_session)


@patch("apps.nuclei_network.collector.run_capped")
@patch("apps.nuclei_network.collector.Port")
def test_collect_timeout_raises(MockPort, mock_run, mock_session):
    """A wall-clock timeout must surface as ToolTimeout so the scan reports
    'partial' rather than a false-clean network sweep."""
    import subprocess as sp
    from apps.core.workflows.exceptions import ToolTimeout
    port = MagicMock(address="1.2.3.4", port=6379, service="redis")
    MockPort.objects.filter.return_value = [port]
    mock_run.side_effect = sp.TimeoutExpired(cmd="nuclei", timeout=3600)
    with pytest.raises(ToolTimeout):
        collect(mock_session)


@patch("apps.nuclei_network.collector.run_capped")
@patch("apps.nuclei_network.collector.Port")
def test_collect_skips_non_json_lines(MockPort, mock_run, mock_session):
    """Log noise / partial lines in stdout must be skipped, not crash the parse."""
    import json
    port = MagicMock(address="1.2.3.4", port=6379, service="redis")
    MockPort.objects.filter.return_value = [port]
    good = json.dumps({"template-id": "redis-exposure", "info": {"severity": "high"}})
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="[INF] running templates\n" + good + "\nnot-json{\n",
        stderr="",
    )
    records = collect(mock_session)
    assert len(records) == 1
    assert records[0]["template-id"] == "redis-exposure"


# ---------------------------------------------------------------------------
# Analyzer — raw nuclei JSON → Finding, dedup, severity fallback, Port FK
# ---------------------------------------------------------------------------

from apps.nuclei_network.analyzer import analyze


def _net_record(template_id="redis-exposure", name="Redis Exposure",
                severity="high", matched_at="1.2.3.4:6379",
                cve_ids=None, cvss_score=None, info="__default__"):
    """Build a realistic nuclei network JSON record. Pass info=None to simulate
    a record whose entire "info" object is JSON null."""
    if info == "__default__":
        classification = {}
        if cve_ids:
            classification["cve-id"] = cve_ids
        if cvss_score is not None:
            classification["cvss-score"] = cvss_score
        info = {
            "name": name,
            "severity": severity,
            "description": "desc",
            "remediation": "fix",
            "classification": classification,
        }
    return {
        "template-id": template_id,
        "info": info,
        "matched-at": matched_at,
        "host": matched_at,
        "matcher-name": "",
        "extracted-results": [],
    }


@pytest.mark.django_db
class TestNucleiNetworkAnalyzer:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4", port=6379,
                            protocol="tcp", state="open", is_web=False, source="naabu")
        return sess

    def test_empty_records(self):
        sess = self._make_session()
        assert analyze(sess, []) == []

    def test_basic_finding_links_port_fk(self):
        sess = self._make_session()
        findings = analyze(sess, [_net_record()])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "nuclei_network"
        assert f.severity == "high"
        assert f.check_type == "network"
        assert f.port is not None
        assert f.port.port == 6379
        assert f.target == "1.2.3.4:6379"

    def test_cve_record_check_type_and_title(self):
        sess = self._make_session()
        findings = analyze(sess, [_net_record(
            template_id="CVE-2022-0543", name="Redis Lua RCE",
            severity="critical", cve_ids=["CVE-2022-0543"], cvss_score=10.0,
        )])
        f = findings[0]
        assert f.check_type == "cve"
        assert "CVE-2022-0543" in f.title
        assert f.extra["cvss_score"] == 10.0

    def test_deduplication_same_template_and_matched_at(self):
        sess = self._make_session()
        findings = analyze(sess, [_net_record(), _net_record()])
        assert len(findings) == 1

    def test_different_matched_at_not_deduped(self):
        sess = self._make_session()
        findings = analyze(sess, [
            _net_record(matched_at="1.2.3.4:6379"),
            _net_record(matched_at="1.2.3.4:6380"),
        ])
        assert len(findings) == 2

    def test_severity_fallback_unknown_maps_to_info(self):
        sess = self._make_session()
        findings = analyze(sess, [_net_record(severity="totally-bogus")])
        assert findings[0].severity == "info"

    def test_severity_fallback_empty_string_maps_to_info(self):
        sess = self._make_session()
        findings = analyze(sess, [_net_record(severity="")])
        assert findings[0].severity == "info"

    def test_info_null_does_not_crash(self):
        # Regression: a record whose whole "info" object is JSON null used to
        # crash analyze() with AttributeError on None.get(...).
        sess = self._make_session()
        findings = analyze(sess, [_net_record(info=None)])
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert findings[0].check_type == "network"

    def test_matched_at_ipv6_bracketed_no_crash_port_fk_none(self):
        # "[::1]:6379" rsplits to ("[::1]", 6379) which has no Port row → None,
        # but must never raise.
        sess = self._make_session()
        findings = analyze(sess, [_net_record(matched_at="[::1]:6379")])
        assert len(findings) == 1
        assert findings[0].port is None
        assert findings[0].target == "[::1]:6379"

    def test_matched_at_no_colon_port_fk_none(self):
        sess = self._make_session()
        findings = analyze(sess, [_net_record(matched_at="justahost")])
        assert len(findings) == 1
        assert findings[0].port is None

    def test_matched_at_non_numeric_port_fk_none(self):
        # "host:notaport" → int("notaport") raises ValueError, caught → None.
        sess = self._make_session()
        findings = analyze(sess, [_net_record(matched_at="1.2.3.4:notaport")])
        assert len(findings) == 1
        assert findings[0].port is None
