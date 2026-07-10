"""Management command: verify_tools — per-tool health audit for a scan.

Answers one question the dashboard cannot: *is every tool actually working, or
did some silently no-op?* A tool that "completes" in 2 seconds with zero output
is a prime suspect for a missing binary, an empty target list, or a swallowed
crash — indistinguishable from "ran fine, found nothing" if you only look at
status. This command separates the two.

Two independent checks:

1. PREFLIGHT — is each tool's external binary installed and on PATH? This is
   deterministic and instant; a missing binary is the single most common silent
   failure. Runs without any scan.

2. OUTPUT AUDIT — for a given scan session, per tool: did it run to `completed`,
   and did it produce its *expected output type* (asset rows by `source`, not the
   misleading StepResult.findings_count), with cascade-aware root-causing so a
   downstream tool starved of input is blamed on the empty upstream, not itself.

Verdicts:
  PASS      completed + produced its expected output
  PASS(0)   completed, 0 findings — valid for a finding-tool on a clean target
  CASCADE   completed, 0 output because a required upstream tool produced nothing
            (root cause is the named upstream, not this tool)
  SUSPECT   completed but 0 output where output was expected, or a suspiciously
            instant run — likely didn't actually execute
  FAIL      status=failed / errored, or binary missing
  SKIP      not enabled in this workflow
  PENDING   still running

Exit code is non-zero if any tool is FAIL or SUSPECT, so this can gate CI.

Usage:
    manage.py verify_tools                       # latest terminal scan for the default domain
    manage.py verify_tools --domain ast.co.rs
    manage.py verify_tools --session 35
"""

import shutil

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.core.assets.models import IPAddress, Port, Subdomain
from apps.core.findings.models import Finding
from apps.core.scans.models import ScanSession
from apps.core.web_assets.models import URL
from apps.core.workflows.models import WorkflowStepResult
from apps.core.workflows.registry import (
    get_registry,
    get_tool_produces_findings,
    get_tool_requires,
)

# Expected output per tool: how to count what it actually produced for a session.
#   ("finding", None)          -> Finding rows with source == tool key
#   ("asset", Model, "source") -> asset rows in Model with source == given string
#   ("port_service", None)     -> Ports that got a service label (service_detection)
#   ("enrich", None)           -> mutates existing rows in place; no new rows to count
OUTPUT_SPEC = {
    "domain_security": ("finding", None),
    "subfinder": ("asset", Subdomain, "subfinder"),
    "amass": ("asset", Subdomain, "amass"),
    "alterx": ("asset", Subdomain, "alterx"),
    "dnsx": ("asset", IPAddress, "dnsx"),
    "takeover_check": ("finding", None),
    "cloud_assets": ("finding", None),
    "naabu": ("asset", Port, "naabu"),
    "service_detection": ("port_service", None),
    "nmap": ("finding", None),
    "tls_checker": ("finding", None),
    "ssh_checker": ("finding", None),
    "nuclei_network": ("finding", None),
    "httpx": ("asset", URL, "httpx"),
    "historical_urls": ("asset", URL, "historical_urls"),
    "katana": ("asset", URL, "katana"),
    "nuclei": ("finding", None),
    "web_checker": ("finding", None),
    "cve_intel": ("enrich", None),
}

# tool key -> the settings attribute holding its external binary path. Tools
# absent from this map are pure-Python (no binary to preflight).
TOOL_BINARY_SETTING = {
    "subfinder": "TOOL_SUBFINDER",
    "dnsx": "TOOL_DNSX",
    "naabu": "TOOL_NAABU",
    "httpx": "TOOL_HTTPX",
    "katana": "TOOL_KATANA",
    "nmap": "TOOL_NMAP",
    "tls_checker": "TOOL_NMAP",
    "service_detection": "TOOL_NMAP",
    "nuclei": "TOOL_NUCLEI",
    "nuclei_network": "TOOL_NUCLEI",
    "amass": "TOOL_AMASS",
    "alterx": "TOOL_ALTERX",
    "cloud_assets": "TOOL_CLOUD_ENUM",
}

# historical_urls shells out to two binaries.
MULTI_BINARY = {"historical_urls": ["TOOL_GAU", "TOOL_WAYBACKURLS"]}

# Below this wall-clock (seconds), a completed-but-empty external-tool run is
# almost certainly a no-op (missing binary / empty input), not real work.
SUSPICIOUS_FAST = 2.0

DEFAULT_DOMAIN = "ast.co.rs"


class Command(BaseCommand):
    help = "Per-tool health audit: preflight binaries + output verification for a scan"

    def add_arguments(self, parser):
        parser.add_argument("--domain", default=DEFAULT_DOMAIN, help="Reference domain")
        parser.add_argument("--session", type=int, help="Specific ScanSession id to audit")

    # ---- output counting -------------------------------------------------

    def _produced(self, tool, session):
        """Count what `tool` actually produced for `session` (its expected type)."""
        spec = OUTPUT_SPEC.get(tool)
        if spec is None:
            return None
        kind = spec[0]
        if kind == "finding":
            return Finding.objects.filter(session=session, source=tool).count()
        if kind == "asset":
            _, model, src = spec
            return model.objects.filter(session=session, source=src).count()
        if kind == "port_service":
            return Port.objects.filter(session=session).exclude(service="").count()
        if kind == "enrich":
            return None  # nothing new to count
        return None

    # ---- preflight -------------------------------------------------------

    def _binary_ok(self, path):
        # absolute path -> must exist & be executable; bare name -> must be on PATH
        if "/" in path:
            import os

            return os.path.isfile(path) and os.access(path, os.X_OK)
        return shutil.which(path) is not None

    def _run_preflight(self):
        self.stdout.write(self.style.MIGRATE_HEADING("\n== PREFLIGHT: tool binaries =="))
        missing = []
        for tool in sorted(get_registry()):
            names = MULTI_BINARY.get(tool) or (
                [TOOL_BINARY_SETTING[tool]] if tool in TOOL_BINARY_SETTING else []
            )
            if not names:
                self.stdout.write(f"  {tool:20s} (pure-python, no binary)")
                continue
            for setting in names:
                path = getattr(settings, setting, setting)
                if self._binary_ok(path):
                    self.stdout.write(self.style.SUCCESS(f"  {tool:20s} OK   {path}"))
                else:
                    self.stdout.write(self.style.ERROR(f"  {tool:20s} MISSING  {path}"))
                    missing.append(tool)
        return missing

    # ---- output audit ----------------------------------------------------

    def _run_audit(self, session):
        run = getattr(session, "workflow_run", None)
        if run is None:
            self.stdout.write(self.style.ERROR("  session has no workflow_run — cannot audit"))
            return ["<no-run>"]

        steps = {s.tool: s for s in WorkflowStepResult.objects.filter(run=run)}
        produces = get_tool_produces_findings()
        requires = get_tool_requires()
        # cache produced counts so cascade checks don't re-query
        produced_cache = {t: self._produced(t, session) for t in steps}

        self.stdout.write(self.style.MIGRATE_HEADING(
            f"\n== OUTPUT AUDIT: session {session.id} / {session.domain} / "
            f"{session.workflow.name} [{session.status}] =="
        ))
        self.stdout.write(f"  {'tool':20s} {'status':10s} {'out':>5s} {'dur':>7s}  verdict")

        problems = []
        for tool in sorted(steps, key=lambda t: steps[t].order):
            step = steps[tool]
            out = produced_cache.get(tool)
            dur = step.duration_seconds
            durs = f"{dur:.0f}s" if dur is not None else "-"
            outs = "-" if out is None else str(out)

            verdict, note = self._verdict(
                tool, step, out, dur, produces.get(tool, False), requires.get(tool, []),
                produced_cache,
            )
            styler = {
                "PASS": self.style.SUCCESS, "PASS(0)": self.style.SUCCESS,
                "CASCADE": self.style.WARNING, "SKIP": lambda x: x,
                "PENDING": self.style.WARNING,
            }.get(verdict, self.style.ERROR)
            if verdict in ("FAIL", "SUSPECT"):
                problems.append(tool)
            line = f"  {tool:20s} {step.status:10s} {outs:>5s} {durs:>7s}  {verdict}"
            if note:
                line += f"  ({note})"
            self.stdout.write(styler(line))
        return problems

    def _verdict(self, tool, step, out, dur, is_finding_tool, deps, produced_cache):
        if step.status == "skipped":
            return "SKIP", ""
        if step.status in ("pending", "running"):
            return "PENDING", ""
        if step.status == "failed" or step.error:
            return "FAIL", (step.error[:50] if step.error else "status=failed")

        # completed:
        if out is None:  # enrich tool — no rows to count; trust clean completion
            return "PASS", "enrich (no new rows)"
        if out > 0:
            return "PASS", ""

        # completed but produced nothing — is that legitimate?
        empty_dep = next(
            (d for d in deps if produced_cache.get(d) == 0), None
        )
        if empty_dep:
            return "CASCADE", f"0 upstream from {empty_dep}"
        if is_finding_tool:
            # 0 findings is valid on a clean target — unless it was suspiciously instant
            if dur is not None and dur < SUSPICIOUS_FAST:
                return "SUSPECT", f"completed in {dur:.1f}s, 0 findings — likely no-op"
            return "PASS(0)", "ran, target clean"
        # asset producer with satisfied (or no) deps that still made nothing
        return "SUSPECT", "expected assets, produced 0 — check binary/input"

    # ---- entry -----------------------------------------------------------

    def handle(self, *args, **options):
        missing = self._run_preflight()

        if options.get("session"):
            session = ScanSession.objects.filter(id=options["session"]).first()
        else:
            session = (
                ScanSession.objects.filter(domain=options["domain"])
                .exclude(status__in=["pending", "running"])
                .order_by("-start_time")
                .first()
            )
        if session is None:
            self.stdout.write(self.style.ERROR(
                f"\nNo terminal scan found for {options['domain']} — run one first."
            ))
            raise SystemExit(1)

        problems = self._run_audit(session)

        self.stdout.write("")
        if missing:
            self.stdout.write(self.style.ERROR(f"Missing binaries: {', '.join(missing)}"))
        if problems:
            self.stdout.write(self.style.ERROR(
                f"Tools needing attention: {', '.join(problems)}"
            ))
        if not missing and not problems:
            self.stdout.write(self.style.SUCCESS("All tools healthy."))
            return
        raise SystemExit(1)
