"""Breach-exposure collector — two-tier, bring-your-own-key.

Reports which of an org's accounts / how many known breaches are associated with
the target domain, using THIRD-PARTY breach datasets. Sends ZERO packets to the
target — this is passive OSINT, so it needs no authorization.

Two tiers, chosen automatically by whether a HIBP key is configured:

  * FREE (default, no key): XposedOrNot's public breach catalog —
    ``GET {XON_BASE_URL}/breaches?domain=<domain>`` — keyless, no credits. Returns
    the known breaches whose breached organisation matches the domain (breach
    name, date, record count, exposed data types). This is public breach
    metadata only; it carries no individual accounts.
  * AUTHORITATIVE (``HIBP_API_KEY`` set): Have I Been Pwned v3 —
    ``GET {HIBP_BASE_URL}/breacheddomain/<domain>`` with the ``hibp-api-key`` +
    ``user-agent`` headers. Requires the operator's paid HIBP subscription AND
    that they have verified ownership of the domain with HIBP. Returns a map of
    email-alias -> [breach names]. We derive ONLY aggregate counts from it: the
    number of affected accounts and the set of breach names. The alias keys are
    email local-parts (PII) and are NEVER stored or returned.

Design contract (privacy / safety — mirrors apps/hudson_rock):
  * FAIL-GRACEFUL, ALWAYS. Any timeout / non-200 (other than the documented
    404/403 "no data" cases) / exhausted 429 / JSON error returns an empty result
    and NEVER raises. This is additive intelligence — it must never fail a scan.
    There is no binary, so we do NOT raise ToolBinaryMissing / ToolTimeout.
  * Sends the honest OpenEASD User-Agent so the data providers can identify us
    (HIBP additionally REQUIRES a user-agent, else it 403s).
  * Honours HTTP 429 / Retry-After with a short, capped backoff.
  * PRIVACY: the returned dict only ever contains aggregate counts + public
    breach metadata (names/dates/record totals). No email alias, address, or
    credential is ever read out of a response into the result.
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


def _user_agent() -> str:
    return getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")


def _xon_base_url() -> str:
    return getattr(
        settings, "BREACH_CHECK_XON_BASE_URL", "https://api.xposedornot.com/v1"
    ).rstrip("/")


def _hibp_base_url() -> str:
    return getattr(
        settings, "HIBP_BASE_URL", "https://haveibeenpwned.com/api/v3"
    ).rstrip("/")


def _empty() -> dict:
    return {"tier": None, "accounts": 0, "breach_count": 0, "breaches": []}


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _get(url: str, headers: dict, ok_statuses=(200,)):
    """GET a JSON endpoint. Returns (status_code, parsed_json_or_None).

    Never raises. Honours 429 / Retry-After with a short, capped backoff. A
    status in ``ok_statuses`` is parsed as JSON; any other status returns
    (status, None) so the caller can treat documented codes (404/403) as
    "no data" rather than an error.
    """
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("breach_check: request to %s failed: %s", url, exc)
            return (None, None)

        if resp.status_code == 429:
            if attempt >= _MAX_RETRIES:
                logger.warning("breach_check: %s rate-limited (429), retries exhausted", url)
                return (429, None)
            backoff = _DEFAULT_BACKOFF
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    backoff = min(int(retry_after), _MAX_BACKOFF)
                except (ValueError, TypeError):
                    backoff = _DEFAULT_BACKOFF
            logger.info("breach_check: %s 429, backing off %ss", url, backoff)
            time.sleep(backoff)
            continue

        if resp.status_code not in ok_statuses:
            return (resp.status_code, None)

        try:
            return (resp.status_code, resp.json())
        except ValueError as exc:
            logger.warning("breach_check: %s returned non-JSON body: %s", url, exc)
            return (resp.status_code, None)

    return (None, None)


def _year_of(value) -> str:
    """Best-effort 4-digit year from a date-ish string (e.g. '2013-10-04')."""
    s = str(value or "")
    for i in range(len(s) - 3):
        chunk = s[i : i + 4]
        if chunk.isdigit() and chunk.startswith(("19", "20")):
            return chunk
    return ""


def _collect_xposedornot(domain: str) -> dict:
    """Free keyless tier — XposedOrNot public breach catalog for the domain."""
    url = f"{_xon_base_url()}/breaches"
    headers = {"User-Agent": _user_agent(), "Accept": "application/json"}
    # XposedOrNot takes the domain as a query string; requests encodes it.
    status, body = _get(f"{url}?domain={domain}", headers)
    if not isinstance(body, dict):
        return _empty()

    raw = body.get("exposedBreaches")
    if not isinstance(raw, list):
        return _empty()

    breaches = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("breachID") or item.get("breach") or "").strip()
        if not name:
            continue
        breaches.append({
            "name": name,
            "year": _year_of(item.get("breachedDate")),
            "records": _as_int(item.get("exposedRecords")),
        })

    return {
        "tier": "xposedornot",
        "accounts": 0,  # the public catalog has no per-domain account count
        "breach_count": len(breaches),
        "breaches": breaches,
    }


def _collect_hibp(domain: str, key: str) -> dict:
    """Authoritative tier — HIBP breacheddomain. Derives ONLY aggregate counts.

    The response maps email-alias -> [breach names]. We read the NUMBER of aliases
    (affected accounts) and the UNION of breach names. The alias keys themselves
    are email local-parts (PII) and are deliberately never stored / returned.
    """
    url = f"{_hibp_base_url()}/breacheddomain/{domain}"
    headers = {
        "User-Agent": _user_agent(),
        "Accept": "application/json",
        "hibp-api-key": key,
    }
    status, body = _get(url, headers)

    if status == 404:
        # Documented: no breached addresses on the domain — normal, not an error.
        return {"tier": "hibp", "accounts": 0, "breach_count": 0, "breaches": []}
    if status == 403:
        logger.warning(
            "breach_check: HIBP returned 403 for %s — the domain is not verified "
            "on this HIBP account (or the key is invalid). No data.", domain
        )
        return _empty()
    if not isinstance(body, dict):
        return _empty()

    accounts = 0
    breach_names: set[str] = set()
    for _alias, names in body.items():
        # NOTE: _alias is an email local-part (PII) — intentionally discarded. We
        # only count the account and union the (public) breach names.
        accounts += 1
        if isinstance(names, list):
            for n in names:
                if isinstance(n, str) and n.strip():
                    breach_names.add(n.strip())

    breaches = [{"name": n, "year": "", "records": 0} for n in sorted(breach_names)]
    return {
        "tier": "hibp",
        "accounts": accounts,
        "breach_count": len(breaches),
        "breaches": breaches,
    }


def collect(domain: str) -> dict:
    """Return aggregate breach exposure for a domain (counts + public metadata).

    Picks the authoritative HIBP tier when ``HIBP_API_KEY`` is set, else the free
    keyless XposedOrNot tier. Always returns a dict; never raises.
    """
    key = getattr(settings, "HIBP_API_KEY", "")
    if key:
        logger.info("[breach_check] HIBP_API_KEY set — using HIBP breacheddomain for %s", domain)
        return _collect_hibp(domain, key)

    logger.info(
        "[breach_check] no HIBP_API_KEY — using the free XposedOrNot tier for %s "
        "(set HIBP_API_KEY for authoritative per-account counts)", domain
    )
    return _collect_xposedornot(domain)
