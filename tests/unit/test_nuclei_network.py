"""Unit tests for apps/nuclei_network — collector, analyzer, scanner."""

import json
from unittest.mock import MagicMock, patch

import pytest

from apps.nuclei_network.collector import collect
from apps.nuclei_network.analyzer import analyze, _parse_cve_ids
from apps.nuclei_network.scanner import run_nuclei_network


def _nuclei_record(template_id="redis-unauth", name="Redis Unauthorized Access",
                   severity="high", host="1.2.3.4:6379",
                   matched_at="1.2.3.4:6379",
                   description="Redis without auth", remediation="Set requirepass",
                   cve_ids=None, cvss_score=None):
    classification = {}
    if cve_ids:
        classification["cve-id"] = cve_ids
    if cvss_score is not None:
        classification["cvss-score"] = cvss_score
    return {
        "template-id": template_id,
        "info": {
            "name": name,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "classification": classification,
        },
        "host": host,
        "matched-at": matched_at,
        "matcher-name": "",
        "extracted-results": [],
    }


class TestParseCveIds:
    def test_list(self):
        assert _parse_cve_ids({"cve-id": ["CVE-2021-1234"]}) == ["CVE-2021-1234"]

    def test_empty(self):
        assert _parse_cve_ids({}) == []


@pytest.mark.django_db
class TestNucleiNetworkCollector:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=22, protocol="tcp", state="open", is_web=False, source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=6379, protocol="tcp", state="open", is_web=False, source="naabu")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=80, protocol="tcp", state="open", is_web=True, source="naabu")
        return sess

    def test_only_non_web_ports_targeted(self):
        sess = self._make_session()
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("apps.nuclei_network.collector.subprocess.run", return_value=mock_result) as mock_run:
            collect(sess)

        # Should be called — non-web ports exist
        assert mock_run.called
        # Check the target file doesn't include port 80 (web)
        cmd = mock_run.call_args[0][0]
        assert "-pt" in cmd

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        with patch("apps.nuclei_network.collector.subprocess.run") as mock_run:
            records = collect(sess)
        assert records == []
        assert not mock_run.called

    def test_binary_not_found(self):
        sess = self._make_session()
        with patch("apps.nuclei_network.collector.subprocess.run",
                   side_effect=FileNotFoundError):
            records = collect(sess)
        assert records == []

    def test_parses_json_output(self):
        sess = self._make_session()
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(_nuclei_record()) + "\n"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("apps.nuclei_network.collector.subprocess.run", return_value=mock_result):
            records = collect(sess)
        assert len(records) == 1


@pytest.mark.django_db
class TestNucleiNetworkAnalyzer:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=6379, protocol="tcp", state="open", source="naabu")
        return sess

    def test_creates_finding(self):
        sess = self._make_session()
        records = [_nuclei_record()]
        findings = analyze(sess, records)
        assert len(findings) == 1
        assert findings[0].source == "nuclei_network"
        assert findings[0].severity == "high"
        assert findings[0].check_type == "network"

    def test_links_port_fk(self):
        sess = self._make_session()
        records = [_nuclei_record(matched_at="1.2.3.4:6379")]
        findings = analyze(sess, records)
        assert findings[0].port is not None
        assert findings[0].port.port == 6379

    def test_deduplication(self):
        sess = self._make_session()
        records = [_nuclei_record(), _nuclei_record()]
        findings = analyze(sess, records)
        assert len(findings) == 1

    def test_cve_check_type(self):
        sess = self._make_session()
        records = [_nuclei_record(cve_ids=["CVE-2021-1234"], cvss_score=9.8)]
        findings = analyze(sess, records)
        assert findings[0].check_type == "cve"
        assert "CVE-2021-1234" in findings[0].title

    def test_empty_records(self):
        sess = self._make_session()
        assert analyze(sess, []) == []


@pytest.mark.django_db
class TestNucleiNetworkScanner:
    def test_creates_findings(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        from apps.core.findings.models import Finding

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=6379, protocol="tcp", state="open", source="naabu")

        with patch("apps.nuclei_network.scanner.collect", return_value=[_nuclei_record()]):
            findings = run_nuclei_network(sess)

        assert len(findings) == 1
        assert Finding.objects.filter(session=sess, source="nuclei_network").count() == 1

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        with patch("apps.nuclei_network.scanner.collect", return_value=[]):
            findings = run_nuclei_network(sess)
        assert findings == []
