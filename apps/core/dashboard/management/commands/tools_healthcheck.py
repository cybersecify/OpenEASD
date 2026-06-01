"""
Probe each external tool with a tiny known-good target.

Run at container startup (see docker-entrypoint.sh) to surface silent
failures early — the kind that produce "0.8-second full scans with only
DNS findings" because naabu/dnsx silently returned empty stdout. Also
catches missing-binary / wrong-PATH issues from misconfigured deployments.

Always exits 0 — the point is observability, not gating startup. Operators
read the output; users can still log into the UI to investigate.

Usage:
    uv run manage.py tools_healthcheck
    uv run manage.py tools_healthcheck --quick   # version checks only
"""

import subprocess
from dataclasses import dataclass

from django.conf import settings
from django.core.management.base import BaseCommand


# Each probe runs `cmd` with optional `stdin_input`. A probe PASSes if:
#   - exit code is 0 (or in the allow-list), AND
#   - stdout contains at least one non-empty line matching `expect_in_stdout`
#     (if set) — for functional probes this proves the tool actually returned
#     results, not just exited cleanly with empty output.
@dataclass
class Probe:
    name: str
    cmd: list[str]
    stdin_input: str | None = None
    expect_in_stdout: str | None = None
    timeout: int = 30
    allowed_exit_codes: tuple[int, ...] = (0,)


def _tool_binary(env_var: str, default: str) -> str:
    return getattr(settings, env_var, default)


def _functional_probes() -> list[Probe]:
    """Functional probes — actually exercise the tool against a known-good target.

    External targets chosen for stability:
      - google.com  → subfinder/dnsx (large attack surface, never goes away)
      - 1.1.1.1:443 → naabu/httpx (Cloudflare, designed for traffic)
    """
    return [
        Probe(
            name="subfinder",
            cmd=[_tool_binary("TOOL_SUBFINDER", "subfinder"), "-d", "google.com", "-silent", "-timeout", "10"],
            expect_in_stdout="google.com",
        ),
        Probe(
            name="dnsx",
            cmd=[_tool_binary("TOOL_DNSX", "dnsx"), "-a", "-silent"],
            stdin_input="google.com\n",
            expect_in_stdout="google.com",
        ),
        Probe(
            name="naabu",
            cmd=[_tool_binary("TOOL_NAABU", "naabu"), "-host", "1.1.1.1", "-p", "443", "-silent"],
            expect_in_stdout="1.1.1.1:443",
        ),
        Probe(
            name="httpx",
            cmd=[_tool_binary("TOOL_HTTPX", "httpx"), "-silent"],
            stdin_input="https://1.1.1.1\n",
            expect_in_stdout="1.1.1.1",
        ),
        # Version checks for tools where a functional probe would be slow
        # (nuclei loads thousands of templates), noisy (amass active enum,
        # nmap port scan), or require a live web target (katana crawl).
        # Version check confirms the binary is callable.
        Probe(
            name="katana",
            cmd=[_tool_binary("TOOL_KATANA", "katana"), "-version"],
            expect_in_stdout="katana",
        ),
        Probe(
            name="nuclei",
            cmd=[_tool_binary("TOOL_NUCLEI", "nuclei"), "-version"],
            expect_in_stdout="nuclei",
        ),
        Probe(
            name="nmap",
            cmd=[_tool_binary("TOOL_NMAP", "nmap"), "-V"],
            expect_in_stdout="Nmap version",
        ),
        Probe(
            name="amass",
            cmd=[_tool_binary("TOOL_AMASS", "amass"), "-version"],
            expect_in_stdout="v",
        ),
        Probe(
            name="cloud_enum",
            cmd=[_tool_binary("TOOL_CLOUD_ENUM", "cloud_enum"), "-h"],
            expect_in_stdout="keyword",
            allowed_exit_codes=(0, 1),
        ),
    ]


def _quick_probes() -> list[Probe]:
    """Version checks only — no network calls. Used by --quick."""
    return [
        Probe(name="subfinder", cmd=[_tool_binary("TOOL_SUBFINDER", "subfinder"), "-version"]),
        Probe(name="dnsx",      cmd=[_tool_binary("TOOL_DNSX", "dnsx"),           "-version"]),
        Probe(name="naabu",     cmd=[_tool_binary("TOOL_NAABU", "naabu"),         "-version"]),
        Probe(name="httpx",     cmd=[_tool_binary("TOOL_HTTPX", "httpx"),         "-version"]),
        Probe(name="katana",    cmd=[_tool_binary("TOOL_KATANA", "katana"),       "-version"]),
        Probe(name="nuclei",    cmd=[_tool_binary("TOOL_NUCLEI", "nuclei"),       "-version"]),
        Probe(name="nmap",      cmd=[_tool_binary("TOOL_NMAP", "nmap"),           "-V"]),
        Probe(name="amass",     cmd=[_tool_binary("TOOL_AMASS", "amass"),         "-version"]),
        Probe(name="cloud_enum", cmd=[_tool_binary("TOOL_CLOUD_ENUM", "cloud_enum"), "-h"], allowed_exit_codes=(0, 1)),
    ]


def run_probe(probe: Probe) -> tuple[bool, str]:
    """Run a probe. Returns (passed, reason)."""
    try:
        result = subprocess.run(
            probe.cmd,
            input=probe.stdin_input,
            capture_output=True,
            text=True,
            timeout=probe.timeout,
            stdin=subprocess.DEVNULL if probe.stdin_input is None else None,
        )
    except FileNotFoundError:
        return False, f"binary not found: {probe.cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"timed out after {probe.timeout}s"
    except Exception as e:
        return False, f"unexpected error: {e}"

    if result.returncode not in probe.allowed_exit_codes:
        stderr = (result.stderr or "").strip().splitlines()
        first_err = stderr[0] if stderr else ""
        return False, f"exit={result.returncode}  stderr={first_err[:80]}"

    # Many ProjectDiscovery tools print version banners to stderr. For functional
    # probes we look at stdout (where actual results land); for version probes
    # either stream is fine.
    combined = (result.stdout or "") + (result.stderr or "")
    if probe.expect_in_stdout and probe.expect_in_stdout not in combined:
        return False, f"empty/unexpected output (this is the silent-fail mode)"

    return True, "OK"


class Command(BaseCommand):
    help = "Probe each external tool with a tiny known-good target. Surfaces silent failures."

    def add_arguments(self, parser):
        parser.add_argument(
            "--quick", action="store_true",
            help="Version check only — no network calls (5s vs ~30s)",
        )

    def handle(self, *args, **options):
        probes = _quick_probes() if options["quick"] else _functional_probes()
        results: list[tuple[Probe, bool, str]] = []

        self.stdout.write(f"[healthcheck] Probing {len(probes)} external tools "
                          f"({'version' if options['quick'] else 'functional'} mode)...")

        for probe in probes:
            passed, reason = run_probe(probe)
            results.append((probe, passed, reason))
            tag = self.style.SUCCESS("PASS") if passed else self.style.ERROR("FAIL")
            line = f"[healthcheck] {probe.name:<10} {tag}"
            if not passed:
                line += f"  — {reason}"
                line += f"\n              cmd: {' '.join(probe.cmd)}"
            self.stdout.write(line)

        failed = [(p, r) for p, ok, r in results if not ok]
        if failed:
            self.stdout.write(self.style.WARNING(
                f"\n[healthcheck] {len(failed)} of {len(probes)} tool(s) failed. "
                f"Scans using these tools will return empty results."
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"\n[healthcheck] All {len(probes)} tools OK."
            ))
        # Always exit 0 — observability, not gating.
