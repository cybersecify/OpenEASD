"""GitHub Org Recon collector — passive, two-tier (free + BYO-token).

Enumerates the target org's PUBLIC GitHub repos via GitHub's official REST API and
pulls lightweight metadata (+ a small, capped set of well-known config files) so the
analyzer can surface exposed infrastructure references (internal hostnames /
subdomains, cloud-bucket URLs, API endpoints) found in that public code/config.

Two tiers, chosen automatically by whether a token is configured:

  * FREE (default, no token): unauthenticated GitHub API, 60 requests/hr. We cap
    total requests (``GITHUB_MAX_REQUESTS``) and repos (``GITHUB_MAX_REPOS``) to stay
    well under it — every deployment gets useful recon out of the box.
  * ENHANCED (``GITHUB_TOKEN`` set): authenticated API, 5000 requests/hr — deeper
    repo + file coverage within the same caps.

Design contract (mirrors apps/shodan, apps/hudson_rock — additive intelligence):
  * FAIL-GRACEFUL, ALWAYS. Any timeout / non-200 / exhausted rate-limit / JSON error
    is logged and skipped; the collector never raises. There is no binary, so it does
    NOT raise ToolBinaryMissing / ToolTimeout.
  * Uses ONLY GitHub's official API (never scrapes, never touches the target) and
    sends the honest OpenEASD User-Agent so GitHub can identify us — GitHub rejects
    requests with no UA. Honours GitHub's rate limits (403/429 + X-RateLimit-*).
  * A 404 means "no such org/user/file" — normal, not an error.
"""

import base64
import logging
import time

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds, per call
_MAX_RETRIES = 2  # extra attempts after a rate-limit response
_DEFAULT_BACKOFF = 2  # seconds, when no Retry-After header
_MAX_BACKOFF = 10  # cap the honoured Retry-After so we never stall a scan

_PER_PAGE = 100  # GitHub's max page size for repo listings
_DEFAULT_MAX_REPOS = 50  # cap repos inspected per scan
_DEFAULT_MAX_REQUESTS = 100  # hard ceiling on total API calls per scan (free-tier guard)
_MAX_FILES_PER_REPO = 4  # capped well-known config files fetched per repo
_MAX_FILE_BYTES = 200_000  # skip config files larger than this (bound bytes parsed)

# Well-known, low-risk config files most likely to carry infra references. Bounded
# by _MAX_FILES_PER_REPO — we never fetch a repo's full tree.
_WELL_KNOWN_FILES = (
    "README.md",
    ".env.example",
    ".env.sample",
    "docker-compose.yml",
    ".github/workflows/ci.yml",
)


def _api_base() -> str:
    return getattr(settings, "GITHUB_API_BASE", "https://api.github.com").rstrip("/")


def _user_agent() -> str:
    return getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")


def _headers() -> dict:
    headers = {
        "User-Agent": _user_agent(),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = getattr(settings, "GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _max_repos() -> int:
    return getattr(settings, "GITHUB_MAX_REPOS", _DEFAULT_MAX_REPOS) or _DEFAULT_MAX_REPOS


def _max_requests() -> int:
    return getattr(settings, "GITHUB_MAX_REQUESTS", _DEFAULT_MAX_REQUESTS) or _DEFAULT_MAX_REQUESTS


def _is_rate_limited(resp) -> bool:
    """A 403/429 that is specifically GitHub's rate limit (vs a hard forbidden)."""
    if resp.headers.get("Retry-After"):
        return True
    remaining = resp.headers.get("X-RateLimit-Remaining")
    return remaining is not None and str(remaining) == "0"


def _get_json(url: str, budget: dict, params: dict | None = None):
    """GET a GitHub API endpoint. Returns parsed JSON, ``{}`` on 404 (no such
    resource), or ``None`` on any failure. Never raises. Honours GitHub's rate
    limits (403/429 + Retry-After / X-RateLimit-*) with capped backoff.

    Counts every call against ``budget`` so the caller can stop before blowing the
    free-tier request ceiling.
    """
    budget["used"] += 1
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.get(url, params=params, headers=_headers(), timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("github_recon: request to %s failed: %s", url, exc)
            return None

        if resp.status_code in (403, 429):
            if _is_rate_limited(resp) and attempt < _MAX_RETRIES:
                backoff = _DEFAULT_BACKOFF
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        backoff = min(int(retry_after), _MAX_BACKOFF)
                    except (ValueError, TypeError):
                        backoff = _DEFAULT_BACKOFF
                logger.info("github_recon: %s rate-limited, backing off %ss", url, backoff)
                time.sleep(backoff)
                continue
            logger.warning("github_recon: %s returned HTTP %s (rate limit / forbidden)", url, resp.status_code)
            return None

        if resp.status_code == 404:
            return {}  # no such org/user/file — normal.

        if resp.status_code != 200:
            logger.warning("github_recon: %s returned HTTP %s", url, resp.status_code)
            return None

        try:
            return resp.json()
        except ValueError as exc:
            logger.warning("github_recon: %s returned non-JSON body: %s", url, exc)
            return None

    return None


def _resolve_org(domain: str) -> str | None:
    """Candidate GitHub org/user login for a domain.

    ``GITHUB_ORG`` (per-deployment override) wins. Otherwise derive from the domain:
    the registrable label is the second-to-last dot label — ``example.com`` and
    ``www.example.com`` both -> ``example``. Multi-part TLDs (``example.co.uk``)
    resolve imperfectly (-> ``co``); set ``GITHUB_ORG`` for those.
    """
    override = getattr(settings, "GITHUB_ORG", "")
    if override:
        return override.strip()
    if not domain:
        return None
    labels = [label for label in str(domain).strip().lower().split(".") if label]
    if len(labels) >= 2:
        return labels[-2]
    if labels:
        return labels[0]
    return None


def _confirm_account(org: str, budget: dict) -> dict:
    """Confirm the login exists as an org or user. Returns a dict with ``login``,
    ``kind`` ('org'|'user'), and ``html_url``; ``login`` is None if unconfirmed."""
    base = _api_base()
    info = _get_json(f"{base}/orgs/{org}", budget)
    if isinstance(info, dict) and info.get("login"):
        return {"login": info["login"], "kind": "org", "html_url": info.get("html_url")}

    if budget["used"] >= budget["max"]:
        return {"login": None, "kind": None, "html_url": None}

    info = _get_json(f"{base}/users/{org}", budget)
    if isinstance(info, dict) and info.get("login"):
        kind = "org" if str(info.get("type", "")).lower() == "organization" else "user"
        return {"login": info["login"], "kind": kind, "html_url": info.get("html_url")}

    return {"login": None, "kind": None, "html_url": None}


def _repo_record(item: dict) -> dict:
    return {
        "name": item.get("name") or "",
        "full_name": item.get("full_name") or "",
        "description": item.get("description") or "",
        "homepage": item.get("homepage") or "",
        "topics": [t for t in (item.get("topics") or []) if isinstance(t, str)],
        "html_url": item.get("html_url") or "",
        "size": item.get("size") or 0,
        "files": [],
    }


def _list_repos(login: str, kind: str, budget: dict) -> list[dict]:
    """Paginate the account's PUBLIC repos, capped at GITHUB_MAX_REPOS. Skips forks
    (their infra refs belong to the upstream, not the org)."""
    base = _api_base()
    repos_path = f"/orgs/{login}/repos" if kind == "org" else f"/users/{login}/repos"
    repo_type = "public" if kind == "org" else "owner"
    cap = _max_repos()

    repos: list[dict] = []
    page = 1
    while len(repos) < cap and budget["used"] < budget["max"]:
        data = _get_json(
            f"{base}{repos_path}",
            budget,
            params={"type": repo_type, "per_page": _PER_PAGE, "page": page},
        )
        if not isinstance(data, list) or not data:
            break
        for item in data:
            if not isinstance(item, dict) or item.get("fork"):
                continue
            repos.append(_repo_record(item))
            if len(repos) >= cap:
                break
        if len(data) < _PER_PAGE:
            break
        page += 1
    return repos


def _fetch_files(login: str, repo: str, budget: dict) -> list[dict]:
    """Fetch a small, capped set of well-known config files' text via the contents
    API. Bounds both file count (_MAX_FILES_PER_REPO) and bytes (_MAX_FILE_BYTES)."""
    base = _api_base()
    files: list[dict] = []
    attempted = 0
    for path in _WELL_KNOWN_FILES:
        if attempted >= _MAX_FILES_PER_REPO or budget["used"] >= budget["max"]:
            break
        attempted += 1
        data = _get_json(f"{base}/repos/{login}/{repo}/contents/{path}", budget)
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            continue  # {} for 404 (absent), or a directory listing (a list) — skip
        if (data.get("size") or 0) > _MAX_FILE_BYTES or not data.get("content"):
            continue
        try:
            text = base64.b64decode(data["content"]).decode("utf-8", "replace")
        except (ValueError, TypeError) as exc:
            logger.warning("github_recon: could not decode %s in %s: %s", path, repo, exc)
            continue
        files.append({"path": path, "content": text})
    return files


def collect(domain: str) -> dict:
    """Enumerate the target org's public repos + capped config files.

    Returns ``{"org", "org_confirmed", "org_url", "kind", "repos"}``. Always returns
    a dict; never raises.
    """
    org = _resolve_org(domain)
    empty = {"org": org, "org_confirmed": False, "org_url": None, "kind": None, "repos": []}
    if not org:
        logger.info("github_recon: no org resolvable from domain %r — skipping", domain)
        return empty

    budget = {"used": 0, "max": _max_requests()}
    account = _confirm_account(org, budget)
    if not account["login"]:
        logger.info("github_recon: no GitHub org/user '%s' — skipping", org)
        return empty

    login, kind = account["login"], account["kind"]
    repos = _list_repos(login, kind, budget)
    for repo in repos:
        if budget["used"] >= budget["max"]:
            logger.info(
                "github_recon: request budget (%d) reached — %d repo(s) not file-scanned",
                budget["max"], len(repos) - repos.index(repo),
            )
            break
        repo["files"] = _fetch_files(login, repo["name"], budget)

    logger.info(
        "github_recon: org '%s' (%s) — %d public repo(s) inspected in %d API call(s)%s",
        login, kind, len(repos), budget["used"],
        "" if getattr(settings, "GITHUB_TOKEN", "") else " (unauthenticated free tier)",
    )
    return {
        "org": login,
        "org_confirmed": True,
        "org_url": account["html_url"] or f"https://github.com/{login}",
        "kind": kind,
        "repos": repos,
    }
