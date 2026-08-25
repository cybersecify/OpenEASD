"""Nuclei binary execution — data collection layer.

Runs the nuclei binary against web URLs discovered by httpx (Phase 5).
Nuclei scans for web vulnerabilities using community templates:
  - CVEs, misconfigurations, exposures, default credentials
  - Tech-specific checks (WordPress, Jira, etc.)
  - Security header issues, open redirects, SSRF, etc.
"""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout
from apps.core.workflows.proc import run_capped

logger = logging.getLogger(__name__)

# Wall-clock cap for the whole nuclei run. Raised from 30m to 2h: on real
# web-bearing targets nuclei is the single highest-value tool (tens of findings
# each) but the old 30m wall SIGKILL'd it at ~4% done, reporting a false 0.
# Time is not the constraint here — value and not
# missing findings are — and this stays under the 4h worker/watchdog budget
# even with nuclei_network (1h) also in the Full Scan. If a very large target
# still exceeds it, the collector raises ToolTimeout so the scan reports
# `partial` honestly rather than a misleading 0.
TIMEOUT = 21600       # fallback wall-clock cap (6h); settings.NUCLEI_TIMEOUT overrides
REQUEST_TIMEOUT = 5   # seconds per HTTP request (nuclei -timeout)
# Lowered 150 -> 100 to be gentler on targets. Observed hosts already self-
# throttle to ~85-95 rps so this rarely binds, but it caps load on hosts that
# could absorb more. 100 rps still completes the full template set on a
# large-target worst case (~330k requests) well within the 2h cap.
RATE_LIMIT = 100      # fallback -rate-limit; the resource profile overrides it
CONCURRENCY = 25      # fallback -c; the resource profile overrides it
# Actual values come from settings.NUCLEI_CONCURRENCY / NUCLEI_RATE_LIMIT, which
# the resource PROFILE resolves (low 10/40, balanced 25/100, high 40/150). Rate
# stays polite even on 'high' — a big box is no licence to hammer the target.


# The hardened, child-escape-proof runner lives in apps.core.workflows.proc
# (run_capped) so nuclei_network — the same binary — gets the same anti-wedge
# protection instead of a plain subprocess.run that can hang the worker.


def _select_targets(session) -> list[str]:
    """Deduped URL list for nuclei: live-probed (httpx) URLs first, then archived/
    crawled ones, capped at NUCLEI_MAX_TARGETS. The cap is logged, never silent —
    a large surface at the polite rate would otherwise blow past the wall-clock.
    """
    from apps.core.web_assets.models import URL

    live = list(URL.objects.filter(session=session, source="httpx").values_list("url", flat=True))
    rest = list(URL.objects.filter(session=session).exclude(source="httpx").values_list("url", flat=True))
    targets = list(dict.fromkeys(live + rest))  # dedupe, live-probed first

    # No cap by default (NUCLEI_MAX_TARGETS=0): scan the whole surface. Only
    # truncate if a deployment explicitly opts in — and then log it, never silent.
    cap = getattr(settings, "NUCLEI_MAX_TARGETS", 0)
    if cap and len(targets) > cap:
        logger.warning(
            f"[nuclei:{session.id}] Capping {len(targets)} URLs to {cap} "
            f"(live-probed first); {len(targets) - cap} not scanned this run"
        )
        targets = targets[:cap]
    return targets


def collect(session) -> list[dict]:
    """
    Run nuclei against all web URLs from the httpx phase.

    Builds targets from URL.objects for this session, writes them to a temp
    file, and runs nuclei in JSON output mode.

    Returns list of raw nuclei JSON records (one per finding).
    """
    binary = getattr(settings, "TOOL_NUCLEI", "nuclei")

    targets = _select_targets(session)
    if not targets:
        logger.info(f"[nuclei:{session.id}] No URLs to scan")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    # Bound nuclei explicitly so it finishes well under TIMEOUT instead of relying
    # on the kill: -timeout caps each request, -rate-limit/-c cap throughput so a
    # host with many ports (e.g. 25 IPs / 27 ports) can't stall the run.
    cmd = [
        binary, "-list", tmp, "-jsonl", "-silent", "-no-color",
        # Never touch the network for templates/version at scan time. Templates
        # are baked into the image; a fresh pod with no templates would otherwise
        # download the whole repo from GitHub mid-scan and hang for hours (the
        # process wedged past its own 30-min cap on a large prod scan).
        "-disable-update-check",
        "-timeout", str(REQUEST_TIMEOUT),
        "-retries", "1",
        "-rate-limit", str(getattr(settings, "NUCLEI_RATE_LIMIT", RATE_LIMIT)),
        "-c", str(getattr(settings, "NUCLEI_CONCURRENCY", CONCURRENCY)),
        # -bulk-size is the REAL peak-memory bound (runtime ≈ c × bulk × per-host
        # buffer). nuclei parses ALL ~13.5k templates up front regardless (~500 MB
        # fixed), so -severity does NOT shrink that startup parse — it cuts the
        # EXECUTED set (fewer requests → no TIMEOUT). What keeps the box from
        # FREEZING is GOMEMLIMIT + a small bulk-size, not -severity.
        "-bulk-size", str(getattr(settings, "NUCLEI_BULK_SIZE", 15)),
        # Scope executed templates by severity (drops ~38% info noise already
        # covered by httpx tech-detect + web_checker). Fixes timeout, not freeze.
        "-severity", getattr(settings, "NUCLEI_SEVERITY", "critical,high,medium"),
        # This run only probes web URLs, so only http templates apply. dns/tcp/ssl
        # are covered by nuclei_network + tls_checker — skipping them here trims the
        # executed set with zero coverage loss.
        "-type", "http",
        # Abandon a host after this many errors instead of retrying every template
        # against a dead/filtered host (cuts wall-clock on blocked targets).
        "-max-host-error", "10",
        # Explicit safety: never run request-heavy fuzzing / DoS / intrusive
        # templates (also excluded by nuclei's default .nuclei-ignore).
        "-exclude-tags", "dos,fuzzing,intrusive",
        # Honest scanner identity so a target can allowlist us deliberately.
        # Note: templates that hard-set their own User-Agent are not overridden.
        "-H", f"User-Agent: {getattr(settings, 'OPENEASD_USER_AGENT', 'OpenEASD/1.0')}",
    ]
    logger.info(f"[nuclei:{session.id}] Scanning {len(targets)} web targets")

    try:
        # Cap nuclei's Go heap on low-memory hosts (env unchanged on balanced/high).
        from apps.core.workflows.proc_env import go_memory_env
        timeout = getattr(settings, "NUCLEI_TIMEOUT", TIMEOUT)
        result = run_capped(cmd, timeout, env=go_memory_env())
    except FileNotFoundError:
        logger.error(f"[nuclei:{session.id}] Binary not found: {binary}")
        raise ToolBinaryMissing(f"nuclei binary not found: {binary}")
    except subprocess.TimeoutExpired:
        logger.error(f"[nuclei:{session.id}] Timed out after {timeout}s")
        raise ToolTimeout(f"nuclei timed out after {timeout}s")
    finally:
        os.unlink(tmp)

    # Surface stderr regardless of exit code: nuclei routinely exits 0 while
    # logging "could not load N templates" / interactsh failures to stderr, which
    # is silent under-coverage if only checked on nonzero rc.
    if result.stderr and result.stderr.strip():
        logger.warning(f"[nuclei:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            records.append(data)
        except json.JSONDecodeError:
            logger.debug(f"[nuclei:{session.id}] Skipping non-JSON line: {line[:100]}")
            continue

    logger.info(f"[nuclei:{session.id}] Parsed {len(records)} raw findings")
    return records
