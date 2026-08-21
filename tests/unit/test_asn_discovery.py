"""Unit tests for apps/asn_discovery — collector, analyzer, and scanner.

No real network calls: subprocess is always mocked.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from apps.asn_discovery.analyzer import analyze
from apps.asn_discovery.collector import (
    _derive_org,
    _parse_asns,
    _parse_cidrs,
    collect,
)
from apps.asn_discovery.scanner import run_asn_discovery


def _session(domain="example.com"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, scan_type="full")


def _completed(stdout="", stderr="", returncode=0):
    """Mock a subprocess.run CompletedProcess-like object."""
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


# ---------------------------------------------------------------------------
# Helpers / parsing
# ---------------------------------------------------------------------------

class TestParsing:
    def test_derive_org_from_domain(self):
        assert _derive_org("example.com") == "example"
        assert _derive_org("EXAMPLE.CO.UK") == "example"
        assert _derive_org("") == ""

    def test_parse_asns_standard_format(self):
        lines = [
            "714, APPLE-ENGINEERING - Apple Inc.",
            "6185, APPLE-AUSTIN - Apple Inc.",
        ]
        records = _parse_asns(lines)
        assert records == [
            {"asn": 714, "description": "APPLE-ENGINEERING - Apple Inc."},
            {"asn": 6185, "description": "APPLE-AUSTIN - Apple Inc."},
        ]

    def test_parse_asns_dedupes(self):
        lines = ["714, ORG-A", "714, ORG-A duplicate"]
        records = _parse_asns(lines)
        assert len(records) == 1
        assert records[0]["asn"] == 714

    def test_parse_asns_bare_asn_format(self):
        records = _parse_asns(["AS12345 Example Org"])
        assert records[0]["asn"] == 12345
        assert "Example Org" in records[0]["description"]

    def test_parse_asns_skips_garbage(self):
        assert _parse_asns(["", "not an asn line", "no leading number"]) == []

    def test_parse_cidrs_bare_lines(self):
        cidrs = _parse_cidrs(["17.0.0.0/8", "17.253.0.0/16"])
        assert cidrs == ["17.0.0.0/8", "17.253.0.0/16"]

    def test_parse_cidrs_ipv6(self):
        cidrs = _parse_cidrs(["2620:149::/32"])
        assert cidrs == ["2620:149::/32"]

    def test_parse_cidrs_columnar_and_dedup(self):
        cidrs = _parse_cidrs([
            "714, 17.0.0.0/8, extra",
            "17.0.0.0/8",  # duplicate token
        ])
        assert cidrs == ["17.0.0.0/8"]

    def test_parse_cidrs_skips_invalid(self):
        assert _parse_cidrs(["not-a-cidr", "999.999.0.0/8", "plain"]) == []


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAsnDiscoveryCollector:
    def test_happy_path_two_step(self):
        sess = _session()
        org_out = _completed(stdout="714, APPLE - Apple Inc.\n")
        asn_out = _completed(stdout="17.0.0.0/8\n17.253.0.0/16\n")
        with patch(
            "apps.asn_discovery.collector.subprocess.run",
            side_effect=[org_out, asn_out],
        ) as mock_run:
            records = collect(sess)
        # First call: -org example ; second call: -asn 714
        assert mock_run.call_args_list[0][0][0][:3] == ["amass", "intel", "-org"]
        assert mock_run.call_args_list[1][0][0][2:4] == ["-asn", "714"]
        assert len(records) == 1
        assert records[0]["asn"] == 714
        assert records[0]["cidrs"] == ["17.0.0.0/8", "17.253.0.0/16"]

    def test_returns_empty_when_no_asns(self):
        sess = _session()
        with patch(
            "apps.asn_discovery.collector.subprocess.run",
            return_value=_completed(stdout="no results here\n"),
        ) as mock_run:
            records = collect(sess)
        assert records == []
        # Only the -org call runs; no -asn expansion when there are no ASNs.
        assert mock_run.call_count == 1

    def test_raises_on_binary_not_found(self):
        from apps.core.workflows.exceptions import ToolBinaryMissing
        sess = _session()
        with patch(
            "apps.asn_discovery.collector.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            with pytest.raises(ToolBinaryMissing):
                collect(sess)

    def test_raises_on_timeout(self):
        from apps.core.workflows.exceptions import ToolTimeout
        sess = _session()
        with patch(
            "apps.asn_discovery.collector.subprocess.run",
            side_effect=subprocess.TimeoutExpired("amass", 300),
        ):
            with pytest.raises(ToolTimeout):
                collect(sess)

    def test_tolerates_nonzero_returncode(self):
        sess = _session()
        org_out = _completed(stdout="714, ORG\n", stderr="warn", returncode=1)
        asn_out = _completed(stdout="17.0.0.0/8\n", returncode=1)
        with patch(
            "apps.asn_discovery.collector.subprocess.run",
            side_effect=[org_out, asn_out],
        ):
            records = collect(sess)
        assert records[0]["asn"] == 714
        assert records[0]["cidrs"] == ["17.0.0.0/8"]

    def test_asn_with_no_cidrs(self):
        sess = _session()
        org_out = _completed(stdout="714, ORG\n")
        asn_out = _completed(stdout="\n")
        with patch(
            "apps.asn_discovery.collector.subprocess.run",
            side_effect=[org_out, asn_out],
        ):
            records = collect(sess)
        assert records[0]["cidrs"] == []


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAsnDiscoveryAnalyzer:
    def test_builds_one_finding_per_asn(self):
        from apps.core.findings.models import Finding
        sess = _session()
        records = [
            {"asn": 714, "description": "Apple Inc.", "cidrs": ["17.0.0.0/8"]},
            {"asn": 6185, "description": "Apple Austin", "cidrs": []},
        ]
        findings = analyze(sess, records)
        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)
        assert all(f.source == "asn_discovery" for f in findings)
        assert all(f.check_type == "asn" for f in findings)
        assert all(f.severity == "info" for f in findings)

    def test_finding_carries_cidrs_in_extra(self):
        sess = _session()
        records = [{"asn": 714, "description": "Apple", "cidrs": ["17.0.0.0/8", "17.253.0.0/16"]}]
        finding = analyze(sess, records)[0]
        assert finding.target == "AS714"
        assert finding.extra["asn"] == 714
        assert finding.extra["cidrs"] == ["17.0.0.0/8", "17.253.0.0/16"]
        assert finding.extra["cidr_count"] == 2
        assert "17.0.0.0/8" in finding.description

    def test_dedupes_by_asn(self):
        sess = _session()
        records = [
            {"asn": 714, "description": "A", "cidrs": []},
            {"asn": 714, "description": "A-dup", "cidrs": []},
        ]
        assert len(analyze(sess, records)) == 1

    def test_no_auto_scan_note_in_remediation(self):
        """Safe-scope contract: remediation must state ranges aren't auto-scanned."""
        sess = _session()
        finding = analyze(sess, [{"asn": 714, "description": "", "cidrs": ["17.0.0.0/8"]}])[0]
        assert "does not auto-expand" in finding.remediation.lower()

    def test_returns_empty_for_no_records(self):
        sess = _session()
        assert analyze(sess, []) == []


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAsnDiscoveryScanner:
    def test_saves_findings_to_db(self):
        from apps.core.findings.models import Finding
        sess = _session()
        with patch("apps.asn_discovery.scanner.collect", return_value=[
            {"asn": 714, "description": "Apple", "cidrs": ["17.0.0.0/8"]},
        ]):
            saved = run_asn_discovery(sess)
        assert len(saved) == 1
        assert Finding.objects.filter(session=sess, source="asn_discovery").count() == 1

    def test_returns_empty_when_collector_returns_nothing(self):
        sess = _session()
        with patch("apps.asn_discovery.scanner.collect", return_value=[]):
            assert run_asn_discovery(sess) == []
