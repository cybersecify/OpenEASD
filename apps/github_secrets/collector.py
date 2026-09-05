"""GitHub public-secret collector — passive, bring-your-own-key.

Searches PUBLIC GitHub for secrets attributable to the target org, fetches the
matching blobs, and runs gitleaks over them — the same detection engine
js_secrets uses on fetched JavaScript, pointed at the org's public GitHub
footprint instead of the target's own site.

This is PASSIVE: every request goes to GitHub's own REST API (a third party),
never to the target's systems. No packet ever reaches the target, so no
DomainAuthorization is required.

BYOK is MANDATORY here (unlike shodan's free tier): GitHub's code-search API
(``/search/code``) requires authentication. With no ``GITHUB_TOKEN`` the
collector is a logged no-op and returns ``[]`` — a keyless Full Scan is never
broken by this tool.

Design contract (mirrors apps/shodan + apps/hudson_rock — additive intel):
  * FAIL-GRACEFUL for the GitHub API. Any timeout / non-200 / exhausted 429 /
    JSON error is logged and skipped; the API side never raises.
  * Only the gitleaks BINARY raises (ToolBinaryMissing / ToolTimeout), exactly
    like js_secrets — a missing scanner binary is a real config error.
  * Sends the honest OpenEASD User-Agent + the GitHub API version header.
  * Org-scoped by default. A global bare-string search is noisy and is gated
    behind ``GITHUB_SECRETS_GLOBAL_SEARCH`` (default False).
  * All work is bounded: MAX_SEARCH_QUERIES, MAX_FILES, MAX_FILE_BYTES.
"""

import logging
import os
import subprocess
import tempfile
import time

import requests
from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15          # seconds, per GitHub API / raw-blob call
_MAX_RETRIES = 2              # extra attempts after a 429 / secondary-rate-limit
_DEFAULT_BACKOFF = 2          # seconds, when GitHub sends no Retry-After
_MAX_BACKOFF = 15            # cap the honoured Retry-After so we never stall a scan
GITLEAKS_TIMEOUT = 300        # wall-clock cap for the gitleaks run

MAX_SEARCH_QUERIES = 10       # hard bound on code-search calls per session
MAX_FILES = 100              # cap blobs fetched + scanned per session
MAX_FILE_BYTES = 1_000_000   # skip blobs larger than 1 MB
_RESULTS_PER_QUERY = 30       # GitHub search page size we ask for

_DEFAULT_API_BASE = "https://api.github.com"

# Filename qualifiers that most often carry hardcoded secrets. Kept small so we
# stay well inside MAX_SEARCH_QUERIES.
_FILENAME_QUALIFIERS = [
    "filename:.env",
    "filename:.npmrc",
    "filename:credentials",
    "filename:id_rsa",
    "extension:pem",
]


def _user_agent() -> str:
    return getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")


def _headers(token: str, raw: bool = False) -> dict:
    accept = "application/vnd.github.raw" if raw else "application/vnd.github+json"
    return {
        "User-Agent": _user_agent(),
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _api_base() -> str:
    return getattr(settings, "GITHUB_API_BASE", _DEFAULT_API_BASE).rstrip("/")


def _sleep_for_rate_limit(resp) -> float:
    """Compute a capped backoff for a 403/429 rate-limit response.

    Prefers ``Retry-After``; falls back to ``X-RateLimit-Reset`` (epoch secs);
    else a fixed default. Always capped by _MAX_BACKOFF.
    """
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(int(retry_after)), _MAX_BACKOFF)
        except (ValueError, TypeError):
            return _DEFAULT_BACKOFF
    reset = resp.headers.get("X-RateLimit-Reset")
    if reset:
        try:
            delta = int(reset) - int(time.time())
            if delta > 0:
                return min(float(delta), _MAX_BACKOFF)
        except (ValueError, TypeError):
            return _DEFAULT_BACKOFF
    return _DEFAULT_BACKOFF


def _is_rate_limited(resp) -> bool:
    """True when the response is a GitHub rate-limit (429, or 403 with the
    remaining-quota header at zero / a secondary-limit body)."""
    if resp.status_code == 429:
        return True
    if resp.status_code == 403:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining == "0":
            return True
        # Secondary rate limits come back as 403 with a Retry-After header.
        if resp.headers.get("Retry-After"):
            return True
    return False


def _get(url: str, token: str, params: dict | None = None, raw: bool = False):
    """GET a GitHub endpoint. Returns a requests.Response on a final 200, or
    None on any failure / exhausted rate-limit. Never raises. Honours GitHub
    rate limits with capped backoff.
    """
    headers = _headers(token, raw=raw)
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("github_secrets: request to %s failed: %s", url, exc)
            return None

        if _is_rate_limited(resp):
            if attempt >= _MAX_RETRIES:
                logger.warning("github_secrets: %s rate-limited, retries exhausted", url)
                return None
            time.sleep(_sleep_for_rate_limit(resp))
            continue

        if resp.status_code == 404:
            return None  # org / blob not found — normal, caller decides.

        if resp.status_code != 200:
            logger.warning("github_secrets: %s returned HTTP %s", url, resp.status_code)
            return None

        return resp

    return None


def _candidate_org(session) -> tuple[str, bool]:
    """Resolve the org to search and whether it is high-confidence.

    A ``GITHUB_ORG`` setting override is authoritative (high confidence). Else
    we auto-derive from the domain's apex label (e.g. ``acme.com`` -> ``acme``),
    which is a best-effort guess and flagged low-confidence.

    Returns ``(org, confident)``; ``("", False)`` when nothing resolvable.
    """
    override = (getattr(settings, "GITHUB_ORG", "") or "").strip()
    if override:
        return override, True

    domain = (getattr(session, "domain", "") or "").strip().lower()
    if not domain:
        return "", False
    # apex label: strip a leading www., take the label before the first dot.
    if domain.startswith("www."):
        domain = domain[4:]
    label = domain.split(".")[0].strip()
    return label, False


def _confirm_org(org: str, token: str) -> bool:
    """True when ``GET /orgs/{org}`` returns a real org. A 404 (personal
    account / no such org) or any failure returns False — we still allow the
    search to proceed, but log the weaker attribution."""
    resp = _get(f"{_api_base()}/orgs/{org}", token)
    if resp is None:
        return False
    try:
        data = resp.json()
    except ValueError:
        return False
    return isinstance(data, dict) and bool(data.get("login"))


def _build_queries(session, org: str) -> list[str]:
    """Build the org-scoped code-search query strings (bounded).

    Default: ORG-SCOPED ONLY — ``org:{org}`` plus a filename/extension
    qualifier, and one ``org:{org} "{domain}"`` string search. A global
    bare-string search (no ``org:`` qualifier) is noisy and only added when
    ``GITHUB_SECRETS_GLOBAL_SEARCH`` is True.
    """
    queries: list[str] = []
    for qual in _FILENAME_QUALIFIERS:
        queries.append(f"org:{org} {qual}")

    domain = (getattr(session, "domain", "") or "").strip().lower()
    if domain:
        queries.append(f'org:{org} "{domain}"')
        if getattr(settings, "GITHUB_SECRETS_GLOBAL_SEARCH", False):
            # Global (un-scoped) search — noisier, opt-in only.
            queries.append(f'"{domain}"')

    return queries[:MAX_SEARCH_QUERIES]


def _search_code(query: str, token: str) -> list[dict]:
    """Run one ``/search/code`` query. Returns the ``items`` list (may be
    empty). Never raises."""
    resp = _get(
        f"{_api_base()}/search/code",
        token,
        params={"q": query, "per_page": _RESULTS_PER_QUERY},
    )
    if resp is None:
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    items = data.get("items")
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


def _fetch_blob(item: dict, token: str) -> str | None:
    """Fetch a search hit's raw blob content. Returns text, or None on any
    failure / oversized / non-text blob."""
    url = item.get("url")  # GitHub contents API URL for the file
    if not url:
        return None
    resp = _get(url, token, params={"ref": (item.get("sha") or "")}, raw=True)
    if resp is None:
        return None
    content = resp.text or ""
    if not content:
        return None
    if len(content.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
        logger.debug("github_secrets: skipping oversized blob %s", url)
        return None
    return content


def _run_gitleaks(session, tmpdir: str) -> list[dict]:
    """Run gitleaks over ``tmpdir`` and return parsed report records. Only the
    binary being missing / timing out raises (like js_secrets)."""
    import json

    binary = getattr(settings, "TOOL_GITLEAKS", "gitleaks")
    report_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-gh-")
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
        logger.error("[github_secrets:%s] gitleaks binary not found: %s", session.id, binary)
        raise ToolBinaryMissing(f"gitleaks binary not found: {binary}")
    except subprocess.TimeoutExpired:
        logger.error("[github_secrets:%s] gitleaks timed out", session.id)
        raise ToolTimeout(f"gitleaks timed out after {GITLEAKS_TIMEOUT}s")
    else:
        # gitleaks exits 1 when it finds leaks — expected, not an error.
        if result.returncode not in (0, 1) and result.stderr:
            logger.warning(
                "[github_secrets:%s] gitleaks exit=%s stderr: %s",
                session.id, result.returncode, result.stderr[:500],
            )
        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read().strip()
        except OSError:
            text = ""
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            # Best-effort cleanup of the temp report file; already gone is fine.
            pass


def collect(session) -> list[dict]:
    """Search public GitHub for the org's leaked secrets and run gitleaks over
    the hits. Returns raw gitleaks records, each tagged with the GitHub blob
    metadata (``_source_url``, ``_repo``, ``_html_url``). Always returns a list;
    the GitHub API side never raises (only a missing gitleaks binary does).
    """
    token = (getattr(settings, "GITHUB_TOKEN", "") or "").strip()
    if not token:
        # No token -> logged no-op. GitHub code-search requires auth; a keyless
        # Full Scan must not be broken by this tool.
        logger.info(
            "[github_secrets:%s] no GITHUB_TOKEN set — skipping (code-search "
            "needs auth; set a token to enable public-secret discovery)",
            session.id,
        )
        return []

    org, confident = _candidate_org(session)
    if not org:
        logger.info("[github_secrets:%s] no org resolvable from domain — skipping", session.id)
        return []

    org_is_real = _confirm_org(org, token)
    logger.info(
        "[github_secrets:%s] org=%s (confidence=%s, github_org_confirmed=%s)",
        session.id, org, "high" if confident else "low", org_is_real,
    )

    queries = _build_queries(session, org)
    hits: list[dict] = []
    seen_urls: set[str] = set()
    for q in queries:
        for item in _search_code(q, token):
            url = item.get("url") or ""
            if url and url not in seen_urls:
                seen_urls.add(url)
                hits.append(item)
            if len(hits) >= MAX_FILES:
                break
        if len(hits) >= MAX_FILES:
            break

    if not hits:
        logger.info("[github_secrets:%s] no code-search hits for org=%s", session.id, org)
        return []

    logger.info(
        "[github_secrets:%s] %d code-search hit(s) via %d quer(ies) — fetching blobs",
        session.id, len(hits), len(queries),
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        file_map: dict[str, dict] = {}  # filename -> hit metadata
        for i, item in enumerate(hits):
            content = _fetch_blob(item, token)
            if content is None:
                continue
            fname = f"{i}.txt"
            try:
                with open(os.path.join(tmpdir, fname), "w", encoding="utf-8") as f:
                    f.write(content)
            except OSError as exc:
                logger.debug("[github_secrets:%s] write failed: %s", session.id, exc)
                continue
            repo = ((item.get("repository") or {}).get("full_name")) or ""
            file_map[fname] = {
                "source_url": item.get("url") or "",
                "html_url": item.get("html_url") or "",
                "repo": repo,
                "path": item.get("path") or "",
            }

        if not file_map:
            logger.info("[github_secrets:%s] no blobs fetched successfully", session.id)
            return []

        records = _run_gitleaks(session, tmpdir)

    tagged = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        fname = os.path.basename(rec.get("File", "") or "")
        meta = file_map.get(fname, {})
        rec["_source_url"] = meta.get("html_url") or meta.get("source_url") or ""
        rec["_repo"] = meta.get("repo") or ""
        rec["_path"] = meta.get("path") or ""
        tagged.append(rec)
    return tagged
