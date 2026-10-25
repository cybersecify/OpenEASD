"""Offline tests for the limited, read-only LDAP RootDSE metadata plugin."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import subprocess

import pytest

from apps.ldap_enum.analyzer import analyze, _metadata
from apps.ldap_enum.collector import collect, _is_ldap_port
from apps.ldap_enum.scanner import run_ldap_enum
from apps.core.engine.workflows.exceptions import ToolBinaryMissing, ToolTimeout


SESSION = SimpleNamespace(id=81)


@pytest.fixture
def mock_finding_model():
    """Test analyzer output without instantiating Django ORM relations."""
    with patch("apps.ldap_enum.analyzer.Finding",
               side_effect=lambda **kwargs: SimpleNamespace(**kwargs)) as mock:
        yield mock


def port(portnum=389, service="ldap", address="192.0.2.10", **kwargs):
    props = dict(port=portnum, service=service, address=address, state="open",
                 protocol="tcp", is_web=False)
    props.update(kwargs)
    return SimpleNamespace(**props)


def nmap_xml(script_output="supportedLDAPVersion: 3\nnamingContexts: dc=example,dc=org",
             *, portnum=389, name="ldap-rootdse", state="open", extras=""):
    return (f'<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{portnum}">'
            f'<state state="{state}"/><script id="{name}"'
            f' output="{script_output.replace("&", "&amp;").replace(chr(34), "&quot;").replace(chr(10), "&#10;")}"/>{extras}'
            f'</port></ports></host></nmaprun>')


def test_port_service_gate():
    assert _is_ldap_port(port(service="ldap"))
    assert _is_ldap_port(port(service="ldaps"))
    assert _is_ldap_port(port(service="ssl/ldap"))
    assert not _is_ldap_port(port(service="http", portnum=389))
    assert not _is_ldap_port(port(service="ldap", state="closed"))
    assert not _is_ldap_port(port(service="ldap", protocol="udp"))
    assert not _is_ldap_port(port(service="ldap", is_web=True))


def test_collect_only_classified_ldap_ports():
    ports = [port(), port(portnum=636, service="ldaps"),
             port(portnum=443, service="https"), port(address="not-an-ip")]
    with patch("apps.ldap_enum.collector.Port.objects.filter", return_value=ports), \
         patch("apps.ldap_enum.collector.subprocess.run", return_value=SimpleNamespace(
             stdout=nmap_xml(), returncode=0)) as run:
        results = collect(SESSION)
    assert list(results) == ["192.0.2.10"]
    assert set(results["192.0.2.10"][1]) == {389, 636}
    command = run.call_args.args[0]
    assert command[-1] == "192.0.2.10"
    assert "--script" in command
    assert command[command.index("--script") + 1] == "ldap-rootdse"
    assert command[command.index("-p") + 1] == "389,636"
    assert "ldap-search" not in command
    assert "--script-args" not in command
    assert run.call_args.kwargs["timeout"] == 75


def test_no_ldap_ports_means_no_process_invocation():
    with patch("apps.ldap_enum.collector.Port.objects.filter", return_value=[port(service="ssh")]), \
         patch("apps.ldap_enum.collector.subprocess.run") as run:
        assert collect(SESSION) == {}
    run.assert_not_called()


def test_missing_binary_is_explicit_failure():
    with patch("apps.ldap_enum.collector.Port.objects.filter", return_value=[port()]), \
         patch("apps.ldap_enum.collector.subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(ToolBinaryMissing):
            collect(SESSION)


def test_timeout_is_explicit_failure():
    with patch("apps.ldap_enum.collector.Port.objects.filter", return_value=[port()]), \
         patch("apps.ldap_enum.collector.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=75)):
        with pytest.raises(ToolTimeout):
            collect(SESSION)


def test_nonzero_exit_is_explicit_failure():
    with patch("apps.ldap_enum.collector.Port.objects.filter", return_value=[port()]), \
         patch("apps.ldap_enum.collector.subprocess.run", return_value=SimpleNamespace(
             returncode=1, stdout="", stderr="unavailable")):
        with pytest.raises(RuntimeError, match="all failed"):
            collect(SESSION)


def test_partial_failure_retains_success():
    ports = [port(), port(address="192.0.2.11")]
    with patch("apps.ldap_enum.collector.Port.objects.filter", return_value=ports), \
         patch("apps.ldap_enum.collector.subprocess.run", side_effect=[
             SimpleNamespace(returncode=0, stdout=nmap_xml()),
             subprocess.TimeoutExpired(cmd="nmap", timeout=75),
         ]):
        assert list(collect(SESSION)) == ["192.0.2.10"]


def test_metadata_is_whitelisted_deduplicated_and_bounded():
    from defusedxml import ElementTree as ET
    script = ET.fromstring('<script output="namingContexts: dc=example,dc=org&#10;'
                          'namingContexts: dc=example,dc=org&#10;'
                          'ignoredAttribute: secret&#10;supportedLDAPVersion: 3"/>')
    assert _metadata(script) == {
        "namingContexts": ["dc=example,dc=org"],
        "supportedLDAPVersion": ["3"],
    }


def test_nested_nmap_elements_are_supported():
    from defusedxml import ElementTree as ET
    script = ET.fromstring('<script><table><elem key="vendorName">OpenLDAP</elem>'
                          '<elem key="password">secret</elem></table></script>')
    assert _metadata(script) == {"vendorName": ["OpenLDAP"]}


def test_analyze_valid_service_metadata_creates_info_finding(mock_finding_model):
    p = port()
    findings = analyze(SESSION, {p.address: (nmap_xml(), {389: p})})
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "ldap_enum"
    assert finding.check_type == "ldap_rootdse_metadata"
    assert finding.severity == "info"
    assert finding.port is p
    assert finding.target == "192.0.2.10:389"
    assert finding.extra["metadata"]["namingContexts"] == ["dc=example,dc=org"]
    assert "does not" in finding.description  # no unsupported vulnerability claim


@pytest.mark.parametrize("xml", [
    "", "not XML", "<nmaprun>",
    '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>',
])
def test_invalid_or_malicious_xml_is_ignored(xml):
    p = port()
    with pytest.raises(ValueError, match="invalid XML"):
        analyze(SESSION, {p.address: (xml, {389: p})})


def test_xml_size_is_bounded():
    p = port()
    with pytest.raises(ValueError, match="invalid XML"):
        analyze(SESSION, {p.address: ("X" * (2 * 1024 * 1024 + 1), {389: p})})


@pytest.mark.parametrize("xml", [
    nmap_xml(name="http-title"),
    nmap_xml(portnum=636),
    nmap_xml(state="closed"),
    nmap_xml(script_output="userPassword: would-not-be-collected"),
])
def test_unrelated_or_non_metadata_script_does_not_create_finding(xml):
    p = port()
    assert analyze(SESSION, {p.address: (xml, {389: p})}) == []


def test_scanner_saves_only_findings():
    record = object()
    with patch("apps.ldap_enum.scanner.collect", return_value={}) as read, \
         patch("apps.ldap_enum.scanner.analyze", return_value=[record]), \
         patch("apps.ldap_enum.scanner.Finding.objects.bulk_create") as bulk:
        assert run_ldap_enum(SESSION) == [record]
    read.assert_called_once_with(SESSION)
    bulk.assert_called_once_with([record])


def test_scanner_does_not_write_empty_results():
    with patch("apps.ldap_enum.scanner.collect", return_value={}), \
         patch("apps.ldap_enum.scanner.analyze", return_value=[]), \
         patch("apps.ldap_enum.scanner.Finding.objects.bulk_create") as bulk:
        assert run_ldap_enum(SESSION) == []
    bulk.assert_not_called()


def test_registry_marks_ldap_as_active_and_after_detection():
    from apps.ldap_enum.apps import LdapEnumConfig
    meta = LdapEnumConfig.tool_meta
    assert meta["active"] is True
    assert meta["requires"] == ["naabu", "service_detection"]
    assert 7 < meta["phase"] < 8
    assert meta["runner"] == "apps.ldap_enum.scanner.run_ldap_enum"


def test_workflow_migration_adds_default_full_scan_without_duplicates():
    import importlib
    migration = importlib.import_module(
        "apps.core.engine.workflows.migrations.0040_add_ldap_enum_to_full_scan"
    )
    workflow = MagicMock()
    workflow.steps.order_by.return_value.values_list.return_value.first.return_value = 9
    workflows = MagicMock()
    workflows.objects.filter.return_value.first.return_value = workflow
    steps = MagicMock()
    registry = SimpleNamespace(get_model=lambda app, model:
                               workflows if model == "Workflow" else steps)
    migration.add_ldap_enum(registry, None)
    steps.objects.get_or_create.assert_called_once_with(
        workflow=workflow, tool="ldap_enum", defaults={"order": 10, "enabled": True}
    )


def test_valid_xml_and_invalid_xml_returns_only_valid_data(mock_finding_model):
    p = port()
    good = nmap_xml()
    responses = {
        p.address: (good, {389: p}),
        "192.0.2.11": ("<invalid", {389: port(address="192.0.2.11")}),
    }
    findings = analyze(SESSION, responses)
    assert len(findings) == 1
    assert findings[0].target == "192.0.2.10:389"


def test_valid_xml_without_ldap_script_is_not_a_parser_failure():
    p = port()
    assert analyze(SESSION, {p.address: ("<nmaprun />", {389: p})}) == []
