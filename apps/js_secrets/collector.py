"""gitleaks JS-secret collection.

Fetches the JavaScript assets discovered during the scan and runs the gitleaks
binary over them to catch hardcoded API keys / tokens / secrets that nuclei's
path-based templates miss.

Flow:
  1. Filter the session's URLs down to JavaScript files (path ends in ``.js``).
  2. Fetch each JS file over HTTP into a throwaway temp directory.
  3. Run ``gitleaks dir <tmpdir> --report-format json --report-path <out>``.
  4. Return the parsed gitleaks report records, each tagged with the source URL
     it came from (``_source_url``) so the analyzer can build Findings.
"""

import json
import logging
import os
import subprocess
import tempfile
from urllib.parse import urlparse

import requests
import urllib3
from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning from verify=False — we fetch assets from
# hosts whose certs we don't control and don't want to fail closed on.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Bound the work: cap how many JS files we pull and scan per session.
MAX_JS_FILES = 200
FETCH_TIMEOUT = 10   # seconds per HTTP fetch
GITLEAKS_TIMEOUT = 300  # wall-clock cap for the gitleaks run


def _is_js_url(url: str) -> bool:
    """True when the URL's path ends in .js (case-insensitive; ignores query)."""
    path = urlparse(url).path
    return path.lower().endswith(".js")


def _fetch(url: str, user_agent: str) -> str | None:
    """Fetch a single JS file's body. Returns text, or None on any failure."""
    try:
        resp = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            verify=False,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
        )
    except requests.RequestException as e:
        logger.debug(f"[js_secrets] fetch failed for {url}: {e}")
        return None
    if resp.status_code != 200 or not resp.text:
        return None
    return resp.text


def collect(session, urls: list[str]) -> list[dict]:
    """Fetch JS assets from ``urls`` and run gitleaks over them.

    ``urls`` is the full URL list for the session; this filters to .js files
    and caps at MAX_JS_FILES. Returns raw gitleaks report records, each with a
    private ``_source_url`` key naming the JS asset it came from.
    """
    js_urls = [u for u in urls if _is_js_url(u)]
    if not js_urls:
        logger.info(f"[js_secrets:{session.id}] No JavaScript URLs to scan")
        return []

    if len(js_urls) > MAX_JS_FILES:
        logger.info(
            f"[js_secrets:{session.id}] {len(js_urls)} JS URLs found — "
            f"truncating to first {MAX_JS_FILES}"
        )
        js_urls = js_urls[:MAX_JS_FILES]

    user_agent = getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")
    binary = getattr(settings, "TOOL_GITLEAKS", "gitleaks")

    with tempfile.TemporaryDirectory() as tmpdir:
        # filename → source URL, so gitleaks' File field maps back to the URL.
        file_map: dict[str, str] = {}
        for i, url in enumerate(js_urls):
            content = _fetch(url, user_agent)
            if content is None:
                continue
            fname = f"{i}.js"
            try:
                with open(os.path.join(tmpdir, fname), "w", encoding="utf-8") as f:
                    f.write(content)
            except OSError as e:
                logger.debug(f"[js_secrets:{session.id}] write failed for {url}: {e}")
                continue
            file_map[fname] = url

        if not file_map:
            logger.info(f"[js_secrets:{session.id}] No JS files fetched successfully")
            return []

        logger.info(
            f"[js_secrets:{session.id}] Scanning {len(file_map)} fetched JS files with gitleaks"
        )

        # Report goes OUTSIDE the scanned dir so gitleaks never scans its own output.
        report_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
        os.close(report_fd)
        cmd = [
            binary, "dir", tmpdir,
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=GITLEAKS_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            logger.error(f"[js_secrets:{session.id}] Binary not found: {binary}")
            raise ToolBinaryMissing(f"gitleaks binary not found: {binary}")
        except subprocess.TimeoutExpired:
            logger.error(f"[js_secrets:{session.id}] gitleaks timed out")
            raise ToolTimeout(f"gitleaks timed out after {GITLEAKS_TIMEOUT}s")
        else:
            # gitleaks exits non-zero (1) when leaks are found — that's expected,
            # not an execution error. Only log a stderr on unusual exit codes.
            if result.returncode not in (0, 1) and result.stderr:
                logger.warning(
                    f"[js_secrets:{session.id}] gitleaks exit={result.returncode} "
                    f"stderr: {result.stderr[:500]}"
                )
            records = _parse_report(report_path)
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

    # Tag each record with the URL its File came from.
    tagged = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        fname = os.path.basename(rec.get("File", "") or "")
        rec["_source_url"] = file_map.get(fname, "")
        tagged.append(rec)
    return tagged


def _parse_report(report_path: str) -> list[dict]:
    """Read gitleaks' JSON report defensively. Returns a list of records."""
    try:
        with open(report_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read().strip()
    except OSError:
        return []
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [r for r in data if isinstance(r, dict)]
