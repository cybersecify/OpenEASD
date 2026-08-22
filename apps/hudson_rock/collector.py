"""Hudson Rock (Cavalier) collector — queries free, keyless OSINT endpoints.

Two endpoints, both keyless (no API key required):

  1. search-by-domain — aggregate infostealer-exposure counts for a domain
     (employees, users, third_parties, totals, stealer families, last-seen
     dates). Counts only — no plaintext credentials.
  2. urls-by-domain — the compromised (system-level) login URLs associated with
     the domain, e.g. login.<domain>, vpn.<domain>.

Design contract (privacy / safety):
  * FAIL-GRACEFUL, ALWAYS. Any timeout / non-200 / exhausted 429 / JSON error
    returns empty and NEVER raises. This tool is additive intelligence — it must
    never fail a scan. There is no binary, so we do NOT raise ToolBinaryMissing
    / ToolTimeout; we log and return empty.
  * Sends the honest OpenEASD User-Agent so Hudson Rock can identify us.
  * 10s timeout per call; honours HTTP 429 / Retry-After with a short backoff.
"""

import logging
import time

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds, per call
_MAX_RETRIES = 2  # extra attempts after a 429
_DEFAULT_BACKOFF = 2  # seconds, when no Retry-After header
_MAX_BACKOFF = 10  # cap the honoured Retry-After so we never stall a scan


def _base_url() -> str:
    return getattr(
        settings,
        "HUDSON_ROCK_BASE_URL",
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools",
    ).rstrip("/")


def _user_agent() -> str:
    return getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")


def _get_json(path: str, domain: str):
    """GET one Cavalier endpoint, return parsed JSON or None on any failure.

    Never raises. Honours 429 / Retry-After with a short, capped backoff.
    """
    url = f"{_base_url()}/{path}"
    headers = {"User-Agent": _user_agent(), "Accept": "application/json"}
    params = {"domain": domain}

    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url, params=params, headers=headers, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            logger.warning("hudson_rock: request to %s failed: %s", path, exc)
            return None

        if resp.status_code == 429:
            if attempt >= _MAX_RETRIES:
                logger.warning("hudson_rock: %s rate-limited (429), retries exhausted", path)
                return None
            backoff = _DEFAULT_BACKOFF
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    backoff = min(int(retry_after), _MAX_BACKOFF)
                except (ValueError, TypeError):
                    backoff = _DEFAULT_BACKOFF
            logger.info("hudson_rock: %s 429, backing off %ss", path, backoff)
            time.sleep(backoff)
            continue

        if resp.status_code != 200:
            logger.warning("hudson_rock: %s returned HTTP %s", path, resp.status_code)
            return None

        try:
            return resp.json()
        except ValueError as exc:
            logger.warning("hudson_rock: %s returned non-JSON body: %s", path, exc)
            return None

    return None


def collect(domain: str) -> dict:
    """Return {"counts": dict, "urls": list} for a domain.

    Each part is independent: a failure of one endpoint leaves the other intact.
    Always returns a dict (never raises).
    """
    counts = _get_json("search-by-domain", domain)
    urls_raw = _get_json("urls-by-domain", domain)

    return {
        "counts": counts if isinstance(counts, dict) else {},
        "urls": urls_raw,
    }
