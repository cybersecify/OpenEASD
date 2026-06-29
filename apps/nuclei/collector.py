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


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run an external tool, SIGKILL-ing its whole process group on timeout.

    subprocess.run(timeout=...) only signals the *direct* child. If the tool has
    spawned helpers that inherit the stdout pipe, the internal communicate() blocks
    waiting for EOF long past the timeout, and the calling thread wedges — which is
    how a single nuclei step can hang a scan until the session watchdog reaps it.

    start_new_session=True puts the child in its own process group, so on timeout we
    can kill the entire tree and the pipe actually closes. Mirrors subprocess.run's
    contract: returns CompletedProcess, raises FileNotFoundError if the binary is
    missing, re-raises TimeoutExpired after the group is killed.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.communicate()  # reap — the pipe is now closed since the group is dead
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


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
