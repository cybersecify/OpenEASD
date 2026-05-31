"""Unit tests for apps/core/dashboard/management/commands/tools_healthcheck.

Covers the four failure modes the healthcheck is designed to surface:
 - binary missing (FileNotFoundError)
 - subprocess timeout
 - non-zero exit
 - exit-zero-with-empty-stdout (the silent-fail mode that produced the
   "0.8-second full scans with only DNS findings" symptom)
"""

import subprocess
from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command

from apps.core.dashboard.management.commands.tools_healthcheck import (
    Probe,
    run_probe,
)


# ---------------------------------------------------------------------------
# run_probe (unit)
# ---------------------------------------------------------------------------

class TestRunProbe:
    def _mock_result(self, returncode=0, stdout="", stderr=""):
        r = subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)
        return r

    def test_passes_when_exit_zero_and_expected_text_in_stdout(self):
        probe = Probe(name="t", cmd=["tool"], expect_in_stdout="hello")
        with patch("subprocess.run", return_value=self._mock_result(0, stdout="hello world\n")):
            passed, reason = run_probe(probe)
        assert passed is True
        assert reason == "OK"

    def test_passes_when_exit_zero_and_no_expectation(self):
        probe = Probe(name="t", cmd=["tool"])  # version-check style
        with patch("subprocess.run", return_value=self._mock_result(0, stdout="")):
            passed, reason = run_probe(probe)
        assert passed is True

    def test_fails_on_missing_binary(self):
        probe = Probe(name="t", cmd=["/no/such/tool"])
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            passed, reason = run_probe(probe)
        assert passed is False
        assert "binary not found" in reason
        assert "/no/such/tool" in reason

    def test_fails_on_timeout(self):
        probe = Probe(name="t", cmd=["tool"], timeout=5)
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="tool", timeout=5)):
            passed, reason = run_probe(probe)
        assert passed is False
        assert "timed out" in reason
        assert "5s" in reason

    def test_fails_on_non_zero_exit(self):
        probe = Probe(name="t", cmd=["tool"])
        with patch("subprocess.run", return_value=self._mock_result(2, stderr="something broke\n")):
            passed, reason = run_probe(probe)
        assert passed is False
        assert "exit=2" in reason
        assert "something broke" in reason

    def test_fails_on_silent_empty_stdout_with_zero_exit(self):
        """The Mac/Colima symptom — naabu/dnsx exit 0 but return nothing."""
        probe = Probe(name="naabu", cmd=["naabu"], expect_in_stdout="1.1.1.1:443")
        with patch("subprocess.run", return_value=self._mock_result(0, stdout="")):
            passed, reason = run_probe(probe)
        assert passed is False
        assert "silent-fail" in reason

    def test_allowed_exit_codes_let_non_zero_through(self):
        probe = Probe(name="t", cmd=["tool"], allowed_exit_codes=(0, 1))
        with patch("subprocess.run", return_value=self._mock_result(1, stdout="ok")):
            passed, _ = run_probe(probe)
        assert passed is True

    def test_expectation_matches_against_stderr_too(self):
        """Some tools (ProjectDiscovery suite) print version banners to stderr."""
        probe = Probe(name="t", cmd=["tool"], expect_in_stdout="v1.2.3")
        with patch("subprocess.run", return_value=self._mock_result(0, stdout="", stderr="tool v1.2.3\n")):
            passed, _ = run_probe(probe)
        assert passed is True

    def test_passes_stdin_devnull_when_no_input(self):
        """Regression guard for the inherited-stdin silent-fail pattern.

        Tools invoked with no stdin must get stdin=DEVNULL, not the parent's
        stdin — that inheritance is what caused naabu/dnsx to silently return
        zero records when invoked from the Django-Q worker process.
        """
        probe = Probe(name="t", cmd=["tool"])
        with patch("subprocess.run", return_value=self._mock_result(0)) as mock_run:
            run_probe(probe)
        assert mock_run.call_args.kwargs.get("stdin") == subprocess.DEVNULL

    def test_uses_real_stdin_when_input_provided(self):
        probe = Probe(name="t", cmd=["tool"], stdin_input="hello\n")
        with patch("subprocess.run", return_value=self._mock_result(0)) as mock_run:
            run_probe(probe)
        assert mock_run.call_args.kwargs.get("stdin") is None  # input= is used instead
        assert mock_run.call_args.kwargs.get("input") == "hello\n"


# ---------------------------------------------------------------------------
# Command (integration)
# ---------------------------------------------------------------------------

class TestCommand:
    def test_quick_mode_runs_version_checks_only(self, db):
        out = StringIO()
        with patch(
            "apps.core.dashboard.management.commands.tools_healthcheck.run_probe",
            return_value=(True, "OK"),
        ) as mock_probe:
            call_command("tools_healthcheck", "--quick", stdout=out)
        # All 8 quick probes should fire (subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, amass)
        assert mock_probe.call_count == 8
        output = out.getvalue()
        assert "version mode" in output
        assert "All 8 tools OK." in output

    def test_functional_mode_runs_full_probes(self, db):
        out = StringIO()
        with patch(
            "apps.core.dashboard.management.commands.tools_healthcheck.run_probe",
            return_value=(True, "OK"),
        ) as mock_probe:
            call_command("tools_healthcheck", stdout=out)
        assert mock_probe.call_count == 8
        assert "functional mode" in out.getvalue()

    def test_failure_summary_lists_count(self, db):
        out = StringIO()

        def fake_probe(probe):
            return (False, "binary not found") if probe.name == "naabu" else (True, "OK")

        with patch(
            "apps.core.dashboard.management.commands.tools_healthcheck.run_probe",
            side_effect=fake_probe,
        ):
            call_command("tools_healthcheck", "--quick", stdout=out)

        output = out.getvalue()
        assert "FAIL" in output
        assert "naabu" in output
        assert "1 of 8 tool(s) failed" in output

    def test_command_always_exits_zero_even_with_failures(self, db):
        """Healthcheck is observability, not gating — never crashes the boot."""
        out = StringIO()
        with patch(
            "apps.core.dashboard.management.commands.tools_healthcheck.run_probe",
            return_value=(False, "binary not found"),
        ):
            # call_command raises CommandError on non-zero exit; here it should NOT raise
            call_command("tools_healthcheck", "--quick", stdout=out)
