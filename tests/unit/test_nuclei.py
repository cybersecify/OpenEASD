"""Unit tests for apps/nuclei — collector, analyzer, scanner."""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from apps.nuclei.collector import collect
from apps.nuclei.analyzer import analyze, _parse_cve_ids, _parse_host_target
from apps.nuclei.scanner import run_nuclei


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nuclei_record(template_id="tech-detect", name="Tech Detection",
                   severity="info", host="https://example.com",
                   matched_at="https://example.com/path",
                   description="Test finding", remediation="Fix it",
                   cve_ids=None, cvss_score=None, matcher_name=""):
    """Build a realistic nuclei JSON record."""
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
        "matcher-name": matcher_name,
        "extracted-results": [],
        "curl-command": "",
    }


# ---------------------------------------------------------------------------
# Unit tests — no DB needed
# ---------------------------------------------------------------------------

class TestParseCveIds:
    def test_list_of_cves(self):
        assert _parse_cve_ids({"cve-id": ["CVE-2021-1234", "CVE-2021-5678"]}) == [
            "CVE-2021-1234", "CVE-2021-5678"
        ]

    def test_single_string_cve(self):
        assert _parse_cve_ids({"cve-id": "CVE-2021-1234"}) == ["CVE-2021-1234"]

    def test_empty_list(self):
        assert _parse_cve_ids({"cve-id": []}) == []

    def test_missing_key(self):
        assert _parse_cve_ids({}) == []

    def test_none_value(self):
        assert _parse_cve_ids({"cve-id": None}) == []


class TestParseHostTarget:
    def test_matched_at_preferred(self):
        data = {"matched-at": "https://example.com/admin", "host": "https://example.com"}
        assert _parse_host_target(data) == "https://example.com/admin"

    def test_falls_back_to_host(self):
        data = {"matched-at": "", "host": "https://example.com"}
        assert _parse_host_target(data) == "https://example.com"

    def test_empty_both(self):
        assert _parse_host_target({}) == ""


# ---------------------------------------------------------------------------
# Analyzer — DB required
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNucleiAnalyzer:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain
        from apps.core.web_assets.models import URL
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com",
                                       subdomain="www.example.com", source="subfinder")
        URL.objects.create(session=sess, subdomain=sub,
                           url="https://example.com",
                           host="example.com", port_number=443,
                           scheme="https", source="httpx")
        return sess

    def test_basic_finding(self):
        sess = self._make_session()
        records = [_nuclei_record()]
        findings = analyze(sess, records)
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "nuclei"
        assert f.severity == "info"
        assert f.check_type == "web"

    def test_cve_finding(self):
        sess = self._make_session()
        records = [_nuclei_record(
            template_id="CVE-2021-44228",
            name="Log4j RCE",
            severity="critical",
            cve_ids=["CVE-2021-44228"],
            cvss_score=10.0,
        )]
        findings = analyze(sess, records)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert f.check_type == "cve"
        assert "CVE-2021-44228" in f.title
        assert f.extra["cvss_score"] == 10.0

    def test_severity_mapping(self):
        sess = self._make_session()
        for sev in ["info", "low", "medium", "high", "critical"]:
            records = [_nuclei_record(severity=sev, template_id=f"test-{sev}",
                                      matched_at=f"https://example.com/{sev}")]
            findings = analyze(sess, records)
            assert findings[0].severity == sev

    def test_deduplication(self):
        sess = self._make_session()
        records = [_nuclei_record(), _nuclei_record()]  # Same template_id + matched_at
        findings = analyze(sess, records)
        assert len(findings) == 1

    def test_different_templates_not_deduped(self):
        sess = self._make_session()
        records = [
            _nuclei_record(template_id="tech-detect"),
            _nuclei_record(template_id="http-missing-headers"),
        ]
        findings = analyze(sess, records)
        assert len(findings) == 2

    def test_url_fk_linked(self):
        sess = self._make_session()
        records = [_nuclei_record(host="https://example.com")]
        findings = analyze(sess, records)
        assert findings[0].url is not None

    def test_url_fk_none_for_unknown_host(self):
        sess = self._make_session()
        records = [_nuclei_record(host="https://other.com")]
        findings = analyze(sess, records)
        assert findings[0].url is None

    def test_empty_records(self):
        sess = self._make_session()
        findings = analyze(sess, [])
        assert findings == []

    def test_remediation_preserved(self):
        sess = self._make_session()
        records = [_nuclei_record(remediation="Upgrade to latest version")]
        findings = analyze(sess, records)
        assert findings[0].remediation == "Upgrade to latest version"

    def test_long_title_truncated(self):
        sess = self._make_session()
        records = [_nuclei_record(name="A" * 300)]
        findings = analyze(sess, records)
        assert len(findings[0].title) <= 250


# ---------------------------------------------------------------------------
# Collector — mocked subprocess
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNucleiCollector:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain
        from apps.core.web_assets.models import URL
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com",
                                       subdomain="www.example.com", source="subfinder")
        URL.objects.create(session=sess, subdomain=sub,
                           url="https://example.com:443",
                           host="example.com", port_number=443,
                           scheme="https", source="httpx")
        URL.objects.create(session=sess, subdomain=sub,
                           url="http://example.com:80",
                           host="example.com", port_number=80,
                           scheme="http", source="httpx")
        return sess

    def test_builds_targets_from_urls(self):
        sess = self._make_session()
        nuclei_output = json.dumps(_nuclei_record()) + "\n"
        mock_result = MagicMock()
        mock_result.stdout = nuclei_output
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("apps.nuclei.collector._run", return_value=mock_result) as mock_run:
            records = collect(sess)

        assert mock_run.called
        assert len(records) == 1

    def test_empty_session_no_run(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")

        with patch("apps.nuclei.collector._run") as mock_run:
            records = collect(sess)

        assert records == []
        assert not mock_run.called

    def test_binary_not_found_raises(self):
        """A missing binary must surface as ToolBinaryMissing, not a silent [] —
        otherwise the runner marks the step 'completed' and the failure hides."""
        from apps.core.workflows.exceptions import ToolBinaryMissing
        sess = self._make_session()
        with patch("apps.nuclei.collector._run", side_effect=FileNotFoundError):
            with pytest.raises(ToolBinaryMissing):
                collect(sess)

    def test_timeout_raises(self):
        """A wall-clock timeout must surface as ToolTimeout, not a silent [] —
        this is the false-green that made nuclei look 'completed' with 0 findings."""
        import subprocess as sp
        from apps.core.workflows.exceptions import ToolTimeout
        sess = self._make_session()
        with patch("apps.nuclei.collector._run",
                   side_effect=sp.TimeoutExpired(cmd="nuclei", timeout=1800)):
            with pytest.raises(ToolTimeout):
                collect(sess)

    def test_invalid_json_skipped(self):
        sess = self._make_session()
        mock_result = MagicMock()
        mock_result.stdout = "not json\n" + json.dumps(_nuclei_record()) + "\n"
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("apps.nuclei.collector._run", return_value=mock_result):
            records = collect(sess)
        assert len(records) == 1

    def test_cmd_includes_rate_limiting_flags(self):
        """nuclei must be invoked with the bounding flags so it can't run unbounded."""
        sess = self._make_session()
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            captured["timeout"] = timeout
            return MagicMock(stdout="", returncode=0, stderr="")

        with patch("apps.nuclei.collector._run", side_effect=fake_run):
            collect(sess)

        cmd = captured["cmd"]
        for flag in ("-rate-limit", "-c", "-timeout", "-retries"):
            assert flag in cmd, f"missing {flag}"
        assert captured["timeout"] == 7200
        # gentler rate limit for politeness (see collector RATE_LIMIT)
        assert "100" in cmd

    def test_cmd_disables_runtime_template_update(self):
        """nuclei must never download/update templates at scan time.

        Templates are baked into the image; a runtime fetch from GitHub on a
        fresh pod hangs for hours mid-scan. -disable-update-check stops nuclei
        from doing any template/version update check when it runs.
        """
        sess = self._make_session()
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return MagicMock(stdout="", returncode=0, stderr="")

        with patch("apps.nuclei.collector._run", side_effect=fake_run):
            collect(sess)

        assert "-disable-update-check" in captured["cmd"]


# ---------------------------------------------------------------------------
# _run — process-group kill on timeout
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == 'win32', reason="UNIX specific tests")
class TestRunProcessGroupKill:
    def test_kills_process_group_on_timeout(self):
        """On timeout, _run must SIGKILL the process group and re-raise. It must
        use wait() (not communicate()) so an escaped child holding the stdout pipe
        can't block us — the bug that wedged the scan past the timeout."""
        import subprocess as sp
        from apps.nuclei import collector

        fake_proc = MagicMock()
        fake_proc.pid = 4242
        fake_proc.returncode = -9
        # First wait(timeout) raises; second wait (post-kill drain) returns.
        fake_proc.wait.side_effect = [
            sp.TimeoutExpired(cmd="nuclei", timeout=1),
            0,
        ]

        with patch("apps.nuclei.collector.subprocess.Popen", return_value=fake_proc), \
             patch("apps.nuclei.collector.os.getpgid", return_value=4242), \
             patch("apps.nuclei.collector.os.killpg") as mock_killpg:
            with pytest.raises(sp.TimeoutExpired):
                collector._run(["nuclei"], timeout=1)

        mock_killpg.assert_called_once()
        # the post-kill drain wait() must run so the dead process is reaped
        assert fake_proc.wait.call_count == 2
        # must NOT fall back to communicate() (the pipe-blocking call)
        assert not fake_proc.communicate.called

    def test_returns_completed_process_on_success(self):
        from apps.nuclei import collector

        fake_proc = MagicMock()
        fake_proc.pid = 99
        fake_proc.returncode = 0
        fake_proc.wait.return_value = 0

        with patch("apps.nuclei.collector.subprocess.Popen", return_value=fake_proc):
            result = collector._run(["nuclei"], timeout=10)

        assert result.returncode == 0
        # stdout/stderr come from the temp output files (empty under a mocked Popen)
        assert result.stdout == ""
        assert not fake_proc.communicate.called

    def test_real_run_captures_output(self):
        from apps.nuclei import collector
        result = collector._run(["printf", "hello\nworld\n"], timeout=10)
        assert result.returncode == 0
        assert "hello" in result.stdout and "world" in result.stdout

    def test_escaped_child_holding_fd_does_not_hang(self):
        """The exact production bug, as a real process: a grandchild calls setsid()
        to escape the process group and keeps the inherited output fd open while it
        sleeps. communicate() would block on pipe-EOF until the watchdog reap; _run
        must SIGKILL the parent and return within the drain grace regardless."""
        import sys
        import time
        import subprocess as sp
        from apps.nuclei import collector

        script = (
            "import os, sys, time\n"
            "if os.fork() == 0:\n"
            "    os.setsid()\n"          # escape the parent's process group
            "    time.sleep(45)\n"       # keep holding the inherited stdout fd
            "    sys.exit(0)\n"
            "time.sleep(45)\n"           # parent sleeps so our timeout fires on it
        )
        start = time.monotonic()
        with pytest.raises(sp.TimeoutExpired):
            collector._run([sys.executable, "-c", script], timeout=1)
        elapsed = time.monotonic() - start
        # If _run still used communicate(), this would block ~45s. It must not.
        assert elapsed < collector._DRAIN_GRACE, f"hung for {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# Scanner orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNucleiScanner:
    def test_scanner_creates_findings(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain
        from apps.core.web_assets.models import URL
        from apps.core.findings.models import Finding

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com",
                                       subdomain="www.example.com", source="subfinder")
        URL.objects.create(session=sess, subdomain=sub, url="https://example.com",
                           host="example.com", port_number=443, scheme="https", source="httpx")

        fake_records = [_nuclei_record(severity="high")]
        with patch("apps.nuclei.scanner.collect", return_value=fake_records):
            findings = run_nuclei(sess)

        assert len(findings) == 1
        assert Finding.objects.filter(session=sess, source="nuclei").count() == 1

    def test_scanner_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        with patch("apps.nuclei.scanner.collect", return_value=[]):
            findings = run_nuclei(sess)
        assert findings == []
