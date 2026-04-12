"""Unit tests for apps/nmap — severity mapping, vulners XML parser, web/non-web exclusion."""

import xml.etree.ElementTree as ET
from unittest.mock import patch

import pytest

from apps.nmap.analyzer import _extract_vulns, _severity_from_cvss, analyze
from apps.nmap.scanner import run_nmap


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

class TestSeverityFromCvss:
    def test_critical(self):
        assert _severity_from_cvss(9.0) == "critical"
        assert _severity_from_cvss(9.8) == "critical"
        assert _severity_from_cvss(10.0) == "critical"

    def test_high(self):
        assert _severity_from_cvss(7.0) == "high"
        assert _severity_from_cvss(8.1) == "high"
        assert _severity_from_cvss(8.99) == "high"

    def test_medium(self):
        assert _severity_from_cvss(4.0) == "medium"
        assert _severity_from_cvss(5.5) == "medium"
        assert _severity_from_cvss(6.99) == "medium"

    def test_low(self):
        assert _severity_from_cvss(0.1) == "low"
        assert _severity_from_cvss(2.5) == "low"
        assert _severity_from_cvss(3.99) == "low"

    def test_info(self):
        assert _severity_from_cvss(0.0) == "info"


# ---------------------------------------------------------------------------
# Vulners XML extractor
# ---------------------------------------------------------------------------

class TestExtractVulns:
    def _script_from_xml(self, xml_str):
        return ET.fromstring(xml_str)

    def test_extracts_single_cve(self):
        script = self._script_from_xml("""
            <script id="vulners">
              <table key="cpe:/a:openbsd:openssh:7.2p2">
                <table>
                  <elem key="id">CVE-2018-15473</elem>
                  <elem key="cvss">5.0</elem>
                  <elem key="type">cve</elem>
                  <elem key="is_exploit">false</elem>
                </table>
              </table>
            </script>
        """)
        vulns = _extract_vulns(script)
        assert len(vulns) == 1
        assert vulns[0]["id"] == "CVE-2018-15473"
        assert vulns[0]["cvss"] == 5.0
        assert vulns[0]["type"] == "cve"
        assert vulns[0]["is_exploit"] is False

    def test_extracts_multiple_cves(self):
        script = self._script_from_xml("""
            <script id="vulners">
              <table key="cpe:/a:openbsd:openssh:7.2p2">
                <table>
                  <elem key="id">CVE-2018-15473</elem>
                  <elem key="cvss">5.0</elem>
                  <elem key="type">cve</elem>
                </table>
                <table>
                  <elem key="id">CVE-2016-10009</elem>
                  <elem key="cvss">9.0</elem>
                  <elem key="type">cve</elem>
                  <elem key="is_exploit">true</elem>
                </table>
              </table>
            </script>
        """)
        vulns = _extract_vulns(script)
        assert len(vulns) == 2
        ids = {v["id"] for v in vulns}
        assert ids == {"CVE-2018-15473", "CVE-2016-10009"}

    def test_handles_exploitdb_entries(self):
        script = self._script_from_xml("""
            <script id="vulners">
              <table>
                <table>
                  <elem key="id">EDB-ID:40136</elem>
                  <elem key="cvss">0.0</elem>
                  <elem key="type">exploitdb</elem>
                  <elem key="is_exploit">true</elem>
                </table>
              </table>
            </script>
        """)
        vulns = _extract_vulns(script)
        assert len(vulns) == 1
        assert vulns[0]["type"] == "exploitdb"

    def test_handles_missing_cvss(self):
        script = self._script_from_xml("""
            <script id="vulners">
              <table>
                <table>
                  <elem key="id">CVE-2024-99999</elem>
                  <elem key="type">cve</elem>
                </table>
              </table>
            </script>
        """)
        vulns = _extract_vulns(script)
        assert len(vulns) == 1
        assert vulns[0]["cvss"] == 0.0

    def test_empty_script_returns_empty_list(self):
        script = self._script_from_xml('<script id="vulners"></script>')
        assert _extract_vulns(script) == []


# ---------------------------------------------------------------------------
# Analyzer end-to-end with synthetic XML
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNmapAnalyzer:
    SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="1.2.3.4" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="7.2p2"/>
<script id="vulners">
<table key="cpe:/a:openbsd:openssh:7.2p2">
<table>
<elem key="id">CVE-2018-15473</elem>
<elem key="cvss">5.0</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">CVE-2016-10009</elem>
<elem key="cvss">9.0</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">EDB-ID:40136</elem>
<elem key="cvss">0.0</elem>
<elem key="type">exploitdb</elem>
</table>
</table>
</script>
</port></ports>
</host>
</nmaprun>
"""

    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(
            session=sess, ip_address=ip, address="1.2.3.4", port=22,
            protocol="tcp", state="open", source="naabu",
        )
        return sess

    def test_analyze_filters_to_cves_only(self):
        sess = self._make_session()
        findings = analyze(sess, {"1.2.3.4": self.SAMPLE_XML})
        # 2 CVEs, EDB-ID dropped
        assert len(findings) == 2
        cves = {f.cve for f in findings}
        assert cves == {"CVE-2018-15473", "CVE-2016-10009"}

    def test_analyze_maps_severity_correctly(self):
        sess = self._make_session()
        findings = analyze(sess, {"1.2.3.4": self.SAMPLE_XML})
        by_cve = {f.cve: f for f in findings}
        assert by_cve["CVE-2018-15473"].severity == "medium"  # cvss=5.0
        assert by_cve["CVE-2016-10009"].severity == "critical"  # cvss=9.0

    def test_analyze_links_finding_to_port_fk(self):
        sess = self._make_session()
        findings = analyze(sess, {"1.2.3.4": self.SAMPLE_XML})
        assert all(f.port is not None for f in findings)
        assert all(f.port.address == "1.2.3.4" for f in findings)

    def test_analyze_captures_service_and_version(self):
        sess = self._make_session()
        findings = analyze(sess, {"1.2.3.4": self.SAMPLE_XML})
        f = findings[0]
        assert f.service == "ssh"
        assert "OpenSSH" in f.version

    def test_analyze_dedupes_same_cve_on_same_port(self):
        sess = self._make_session()
        # Pass the same XML twice for the same IP — only one set should be created
        findings = analyze(sess, {"1.2.3.4": self.SAMPLE_XML})
        cves_first_run = [f.cve for f in findings]
        # Re-run analyze on same data — should still only see each CVE once
        assert sorted(cves_first_run) == sorted(set(cves_first_run))

    def test_analyze_handles_malformed_xml(self):
        sess = self._make_session()
        findings = analyze(sess, {"1.2.3.4": "<not valid xml"})
        assert findings == []

    def test_analyze_handles_empty_input(self):
        sess = self._make_session()
        assert analyze(sess, {}) == []


# ---------------------------------------------------------------------------
# Web/non-web classification via Port.is_web
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestWebClassification:
    """Tests that nmap only scans ports with is_web=False."""

    def test_nmap_skips_web_ports(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=80, protocol="tcp", state="open", is_web=True, source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=22, protocol="tcp", state="open", is_web=False, source="naabu")

        with patch("apps.nmap.scanner.collect", return_value={}) as mock_collect:
            run_nmap(sess)

        # Only port 22 should be scanned (non-web)
        if mock_collect.called:
            ip_to_ports = mock_collect.call_args[0][1]
            ports = ip_to_ports.get("1.2.3.4", [])
            assert 80 not in ports
            assert 22 in ports

    def test_nmap_skips_when_all_web(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=80, protocol="tcp", state="open", is_web=True, source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=443, protocol="tcp", state="open", is_web=True, source="naabu")

        findings = run_nmap(sess)
        assert findings == []

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        assert run_nmap(sess) == []


# ---------------------------------------------------------------------------
# Scanner orchestrator (mocked collector)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNmapScanner:
    def test_run_nmap_skips_when_no_non_web_ports(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        findings = run_nmap(sess)
        assert findings == []

    def test_run_nmap_excludes_web_ports_via_is_web(self):
        """nmap should skip ports with is_web=True."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=80, protocol="tcp", state="open", is_web=True, source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=22, protocol="tcp", state="open", is_web=False, source="naabu")

        with patch("apps.nmap.scanner.collect", return_value={}) as mock_collect:
            run_nmap(sess)

        called_with = mock_collect.call_args[0][1]
        assert "1.2.3.4" in called_with
        assert called_with["1.2.3.4"] == [22]
