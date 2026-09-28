import pytest
from unittest.mock import patch


def _finding(target="example.com:443", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(session=s, source="nmap", check_type="cve",
                                  severity="high", title="CVE-2023-9999", target=target,
                                  extra=extra if extra is not None else {"cve": "CVE-2023-9999"})


@pytest.mark.django_db
def test_cve_still_reported_is_verified():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nmap.verify._rescan_cves", return_value={"CVE-2023-9999", "CVE-2020-1"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_cve_gone_is_inconclusive():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nmap.verify._rescan_cves", return_value={"CVE-2020-1"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_scan_error_is_inconclusive():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nmap.verify._rescan_cves", side_effect=OSError("nmap missing")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_missing_cve_in_extra_is_inconclusive():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(extra={})
    v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
    assert "missing" in v.detail.lower()


@pytest.mark.django_db
def test_missing_port_in_target_is_inconclusive():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(target="example.com")
    v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
    assert "missing" in v.detail.lower()


@pytest.mark.django_db
def test_verify_finding_calls_rescan_with_host_and_port():
    """Confirms _rescan_cves is invoked against the single host:port parsed
    from finding.target, not the whole session."""
    from apps.nmap.verify import verify_finding

    f = _finding(target="scanme.example.com:22")
    with patch("apps.nmap.verify._rescan_cves", return_value=set()) as mock_rescan:
        verify_finding(f)
    assert mock_rescan.called
    call_args = mock_rescan.call_args
    # host and port must appear somewhere in the call args (positional or kw)
    all_args = list(call_args.args) + list(call_args.kwargs.values())
    assert "scanme.example.com" in all_args
    assert 22 in all_args


@pytest.mark.django_db
def test_rescan_cves_excludes_backported_cve(monkeypatch):
    """The real re-probe rule: _rescan_cves must apply the same backport-aware
    demotion apps/nmap/analyzer.py uses, so a CVE that is patched via a
    distro backport is NOT counted as still-present (else a patched CVE would
    be falsely re-VERIFIED).
    """
    from apps.nmap import verify

    vulnerable_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.4p1" extrainfo="Debian-5+deb11u3"/>
        <script id="vulners" output="...">
          <table key="cpe:/a:openbsd:openssh:8.4p1">
            <table>
              <elem key="id">CVE-2023-9999</elem>
              <elem key="cvss">7.5</elem>
              <elem key="type">cve</elem>
              <elem key="is_exploit">false</elem>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>"""

    monkeypatch.setattr(verify.collector, "collect", lambda session, ip_to_ports: {"10.0.0.5": vulnerable_xml})
    # Force check_backport to report this CVE as backport-patched.
    monkeypatch.setattr(verify, "check_backport", lambda product, version_string, cve: {"backport_applied": True, "first_fixed_in": "5+deb11u3"})

    cves = verify._rescan_cves(session=None, host="10.0.0.5", port=22)
    assert "CVE-2023-9999" not in cves


@pytest.mark.django_db
def test_rescan_cves_includes_non_backported_cve(monkeypatch):
    from apps.nmap import verify

    vulnerable_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
        <script id="vulners" output="...">
          <table key="cpe:/a:nginx:nginx:1.18.0">
            <table>
              <elem key="id">CVE-2023-9999</elem>
              <elem key="cvss">7.5</elem>
              <elem key="type">cve</elem>
              <elem key="is_exploit">false</elem>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>"""

    monkeypatch.setattr(verify.collector, "collect", lambda session, ip_to_ports: {"10.0.0.5": vulnerable_xml})
    monkeypatch.setattr(verify, "check_backport", lambda product, version_string, cve: None)

    cves = verify._rescan_cves(session=None, host="10.0.0.5", port=443)
    assert cves == {"CVE-2023-9999"}


@pytest.mark.django_db
def test_rescan_cves_empty_output_returns_empty_set(monkeypatch):
    from apps.nmap import verify

    monkeypatch.setattr(verify.collector, "collect", lambda session, ip_to_ports: {})

    cves = verify._rescan_cves(session=None, host="10.0.0.5", port=443)
    assert cves == set()
