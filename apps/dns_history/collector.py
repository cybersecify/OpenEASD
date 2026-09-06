"""Historical-DNS collector — queries a passive-DNS dataset for a domain.

Passive OSINT: it asks a third-party passive-DNS provider what A/AAAA/MX records
the domain has resolved to over time; it never sends a packet to the target.

Bring-your-own endpoint: point `DNS_HISTORY_API_URL` at a passive-DNS JSON API
(e.g. a SecurityTrails / self-hosted mirror endpoint that returns a list of
`{type, value, first_seen, last_seen}` records for `?domain=<domain>`). Unset →
the tool no-ops (returns `[]`), like the other BYO passive tools.

Design contract:
  * FAIL-GRACEFUL, ALWAYS. Any missing config / timeout / non-200 / JSON error
    returns `[]` and NEVER raises — this tool is additive intelligence and must
    never fail a scan. There is no binary, so we log and return empty rather than
    raising ToolBinaryMissing / ToolTimeout.
  * Sends the honest OpenEASD User-Agent.
  * 10s timeout.
"""

import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds
_ALLOWED_TYPES = {"A", "AAAA", "MX"}
_MAX_RECORDS = 50  # cap the records returned so a noisy dataset can't flood findings


def _api_url() -> str:
    return getattr(settings, "DNS_HISTORY_API_URL", "").rstrip("/")


def _user_agent() -> str:
    return getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")


def _normalise(records) -> list[dict]:
    """Coerce provider records into `{type, value, first_seen, last_seen}` dicts.

    Accepts either a bare list or a dict wrapping the list under
    `records`/`data`. Only A/AAAA/MX records with a non-empty value are kept;
    no other provider fields are read. Deduped by (type, value), capped.
    """
    if isinstance(records, dict):
        records = records.get("records") or records.get("data") or []
    if not isinstance(records, list):
        return []

    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        rtype = str(item.get("type", "")).strip().upper()
        value = str(item.get("value", "")).strip()
        if rtype not in _ALLOWED_TYPES or not value:
            continue
        key = (rtype, value)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "type": rtype,
            "value": value,
            "first_seen": str(item.get("first_seen", "")).strip(),
            "last_seen": str(item.get("last_seen", "")).strip(),
        })
        if len(out) >= _MAX_RECORDS:
            logger.info("dns_history: record cap (%d) reached — truncating", _MAX_RECORDS)
            break
    return out


def collect(domain: str) -> list[dict]:
    """Return a list of historical DNS records for a domain. Never raises."""
    url = _api_url()
    if not url:
        logger.info("dns_history: DNS_HISTORY_API_URL not set — skipping")
        return []

    headers = {"User-Agent": _user_agent(), "Accept": "application/json"}
    try:
        resp = requests.get(
            url, params={"domain": domain}, headers=headers, timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException as exc:
        logger.warning("dns_history: request failed: %s", exc)
        return []

    if resp.status_code != 200:
        logger.warning("dns_history: provider returned HTTP %s", resp.status_code)
        return []

    try:
        payload = resp.json()
    except ValueError as exc:
        logger.warning("dns_history: non-JSON body: %s", exc)
        return []

    return _normalise(payload)
