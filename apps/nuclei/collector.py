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
import signal
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)

TIMEOUT = 1800        # hard wall-clock cap for the whole nuclei run (30 min)
REQUEST_TIMEOUT = 5   # seconds per HTTP request (nuclei -timeout)
RATE_LIMIT = 150      # max requests/sec across all hosts (nuclei -rate-limit)
CONCURRENCY = 25      # parallel templates (nuclei -c)


_DRAIN_GRACE = 30  # seconds to let a SIGKILL'd process die before we give up


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run an external tool with a timeout that cannot be defeated by child processes.

    Why not subprocess.run / communicate(): communicate() reads stdout/stderr until
    pipe EOF, which only happens once EVERY writer closes the pipe. nuclei spawns
    helpers (interactsh poller, resolvers, headless) that can escape the process
    group and inherit the stdout pipe, so even after we SIGKILL the group the pipe
    never reaches EOF and communicate() blocks forever — the timeout fires but the
    call never returns, wedging the worker thread until the session watchdog reaps it.

    The fix: redirect stdout/stderr to temp FILES (no pipe), and wait() on the
    process itself. wait() returns the moment the direct child exits — it does not
    care about inherited file descriptors — so a SIGKILL always unblocks us. An
    escaped grandchild can leak but can no longer hang the scan.

    Mirrors subprocess.run's contract: returns CompletedProcess, raises
    FileNotFoundError if the binary is missing, re-raises TimeoutExpired after the
    group is killed.
    """
    out_fd, out_path = tempfile.mkstemp(suffix=".nuclei.out")
    err_fd, err_path = tempfile.mkstemp(suffix=".nuclei.err")
    try:
        with os.fdopen(out_fd, "wb") as out_f, os.fdopen(err_fd, "wb") as err_f:
            proc = subprocess.Popen(
                cmd,
                stdout=out_f,
                stderr=err_f,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                try:
                    proc.wait(timeout=_DRAIN_GRACE)
                except subprocess.TimeoutExpired:
                    pass
                raise
        with open(out_path, "r", errors="replace") as f:
            stdout = f.read()
        with open(err_path, "r", errors="replace") as f:
            stderr = f.read()
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    finally:
        for p in (out_path, err_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def collect(session) -> list[dict]:
    """
    Run nuclei against all web URLs from the httpx phase.

    Builds targets from URL.objects for this session, writes them to a temp
    file, and runs nuclei in JSON output mode.

    Returns list of raw nuclei JSON records (one per finding).
    """
    from apps.core.web_assets.models import URL

    binary = getattr(settings, "TOOL_NUCLEI", "nuclei")

    urls = list(URL.objects.filter(session=session).values_list("url", flat=True))
    if not urls:
        logger.info(f"[nuclei:{session.id}] No URLs to scan")
        return []

    # Deduplicate
    targets = sorted(set(urls))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    # Bound nuclei explicitly so it finishes well under TIMEOUT instead of relying
    # on the kill: -timeout caps each request, -rate-limit/-c cap throughput so a
    # host with many ports (ast.co.rs had 25 IPs / 27 ports) can't stall the run.
    cmd = [
        binary, "-list", tmp, "-jsonl", "-silent", "-no-color",
        # Never touch the network for templates/version at scan time. Templates
        # are baked into the image; a fresh pod with no templates would otherwise
        # download the whole repo from GitHub mid-scan and hang for hours (the
        # process wedged past its own 30-min cap on the ast.co.rs prod scan).
        "-disable-update-check",
        "-timeout", str(REQUEST_TIMEOUT),
        "-retries", "1",
        "-rate-limit", str(RATE_LIMIT),
        "-c", str(CONCURRENCY),
    ]
    logger.info(f"[nuclei:{session.id}] Scanning {len(targets)} web targets")

    try:
        result = _run(cmd, TIMEOUT)
    except FileNotFoundError:
        logger.error(f"[nuclei:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[nuclei:{session.id}] Timed out after {TIMEOUT}s")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0 and result.stderr:
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
