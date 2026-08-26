"""Update-available check — compares the running build against the latest
public GitHub release and tells a logged-in operator when their deployment is
behind.

Design notes:
  - The app never self-updates. This is a *heads-up* only: it surfaces the
    latest released version + a link, so the operator can redeploy the image.
  - The GitHub call is cached (LocMemCache, per worker) so a page load does not
    hit the API every time, and rate limits (60/hr unauthenticated) are never a
    problem for a handful of operators.
  - Fully fail-graceful: any error (offline, timeout, rate limit, bad JSON)
    returns "no update info", never raises. A version indicator must never be
    able to break the page it sits on.
"""

import logging

import requests
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

RELEASES_URL = "https://api.github.com/repos/cybersecify/OpenEASD/releases/latest"
_CACHE_KEY = "openeasd:latest_release"
_CACHE_TTL = 6 * 60 * 60  # 6 hours
_TIMEOUT = 4              # seconds — a slow GitHub must not stall the page


def _parse_version(value):
    """Parse '0.10.0' or 'v0.10.0' into a comparable (major, minor, patch) tuple.

    Returns None for placeholders ('dev'/'unknown'/'') or anything that does not
    look like a dotted numeric version — callers treat None as "cannot compare".
    """
    if not value:
        return None
    s = str(value).strip().lstrip("vV")
    if not s or s.lower() in ("dev", "unknown"):
        return None
    parts = s.split(".")
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None


def is_update_available(current, latest):
    """True only when both versions parse AND latest is strictly newer."""
    c = _parse_version(current)
    l = _parse_version(latest)
    if c is None or l is None:
        return False
    return l > c


def get_latest_release(force=False):
    """Return {'version': str, 'url': str} for the newest GitHub release, or None.

    Cached for 6h. Never raises — returns None on any failure so the caller can
    silently omit the indicator.
    """
    if not force:
        cached = cache.get(_CACHE_KEY)
        if cached is not None:
            return cached or None  # cached "" (a prior failure) -> None

    ua = getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")
    try:
        resp = requests.get(
            RELEASES_URL,
            timeout=_TIMEOUT,
            headers={"Accept": "application/vnd.github+json", "User-Agent": ua},
        )
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name")
        if not tag:
            raise ValueError("no tag_name in release payload")
        result = {"version": str(tag).lstrip("vV"), "url": data.get("html_url") or ""}
    except (requests.RequestException, ValueError, KeyError) as exc:
        logger.info("update check failed (non-fatal): %s", exc)
        # Cache the failure briefly so a flapping/offline GitHub does not get
        # hammered on every page load; a short TTL lets it recover soon.
        cache.set(_CACHE_KEY, "", 300)
        return None

    cache.set(_CACHE_KEY, result, _CACHE_TTL)
    return result


def check_for_update():
    """Endpoint-shaped summary: latest version, whether we are behind, and a link.

    Always returns a dict (never raises); missing/uncomparable data yields
    update_available=False with nulls.
    """
    current = getattr(settings, "OPENEASD_VERSION", "dev")
    latest = get_latest_release()
    latest_version = latest["version"] if latest else None
    return {
        "current_version": current,
        "latest_version": latest_version,
        "update_available": is_update_available(current, latest_version),
        "release_url": (latest["url"] if latest else None) or None,
    }
