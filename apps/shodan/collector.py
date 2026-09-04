"""Shodan passive-exposure collector — two-tier, bring-your-own-key.

Queries Shodan's own internet-wide scan dataset for the session's resolved public
IPs. Sends ZERO packets to the target — this is third-party data, so it works in
passive mode with no authorization.

Two tiers, chosen automatically by whether a key is configured:

  * FREE (default, no key): Shodan InternetDB — ``https://internetdb.shodan.io/{ip}``.
    Returns open ports, CPEs, and known CVE ids per IP. No credits, no key. Every
    Docker deployment gets this out of the box.
  * ENHANCED (``SHODAN_API_KEY`` set): the full host API —
    ``https://api.shodan.io/shodan/host/{ip}`` — which adds service banners,
    product/version, and tags on top of ports + CVEs. Capped by ``SHODAN_MAX_IPS``
    to protect the paid plan's query credits.

Design contract (mirrors apps/hudson_rock — additive intelligence):
  * FAIL-GRACEFUL, ALWAYS. Any timeout / non-200 / exhausted 429 / JSON error on
    an IP is logged and skipped; the collector never raises. There is no binary,
    so it does NOT raise ToolBinaryMissing / ToolTimeout.
  * Sends the honest OpenEASD User-Agent.
  * A 404 from Shodan means "no data for this IP" — normal, not an error.
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

_INTERNETDB_URL = "https://internetdb.shodan.io"
_HOST_API_URL = "https://api.shodan.io/shodan/host"
_DEFAULT_MAX_IPS = 50  # paid-tier query-credit guard


def _user_agent() -> str:
    return getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")


def _get_json(url: str, params: dict | None = None):
    """GET a Shodan endpoint. Returns parsed JSON, {} on 404 (no data), or None
    on any failure. Never raises. Honours 429 / Retry-After with capped backoff.
    """
    headers = {"User-Agent": _user_agent(), "Accept": "application/json"}
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("shodan: request to %s failed: %s", url, exc)
            return None

        if resp.status_code == 429:
            if attempt >= _MAX_RETRIES:
                logger.warning("shodan: %s rate-limited (429), retries exhausted", url)
                return None
            backoff = _DEFAULT_BACKOFF
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    backoff = min(int(retry_after), _MAX_BACKOFF)
                except (ValueError, TypeError):
                    backoff = _DEFAULT_BACKOFF
            time.sleep(backoff)
            continue

        if resp.status_code == 404:
            return {}  # Shodan has no record for this IP — normal.

        if resp.status_code != 200:
            logger.warning("shodan: %s returned HTTP %s", url, resp.status_code)
            return None

        try:
            return resp.json()
        except ValueError as exc:
            logger.warning("shodan: %s returned non-JSON body: %s", url, exc)
            return None

    return None


def _session_ips(session) -> list[str]:
    """Distinct resolved public IPs for the session (dnsx already filtered these
    to public-only). Sorted for deterministic ordering / capping."""
    from apps.core.assets.models import IPAddress

    ips = IPAddress.objects.filter(session=session).values_list("address", flat=True)
    return sorted({ip for ip in ips if ip})


def _normalize_internetdb(ip: str, d: dict) -> dict:
    """Shape an InternetDB response into the common host record."""
    return {
        "ip": ip,
        "tier": "internetdb",
        "ports": sorted({p for p in (d.get("ports") or []) if isinstance(p, int)}),
        "cpes": [c for c in (d.get("cpes") or []) if isinstance(c, str)],
        "hostnames": [h for h in (d.get("hostnames") or []) if isinstance(h, str)],
        "tags": [t for t in (d.get("tags") or []) if isinstance(t, str)],
        "vulns": sorted({v for v in (d.get("vulns") or []) if isinstance(v, str)}),
        "services": [],  # InternetDB carries no banner detail
    }


def _normalize_host(ip: str, d: dict) -> dict:
    """Shape a full host-API response into the common host record."""
    services = []
    for item in (d.get("data") or []):
        if not isinstance(item, dict):
            continue
        services.append({
            "port": item.get("port"),
            "product": (item.get("product") or "").strip(),
            "version": (item.get("version") or "").strip(),
            "transport": (item.get("transport") or "").strip(),
        })
    # The host API's top-level `vulns` may be a dict {cve: {...}} or a list.
    vulns = d.get("vulns")
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())
    return {
        "ip": ip,
        "tier": "host",
        "ports": sorted({p for p in (d.get("ports") or []) if isinstance(p, int)}),
        "cpes": [c for c in (d.get("cpes") or []) if isinstance(c, str)],
        "hostnames": [h for h in (d.get("hostnames") or []) if isinstance(h, str)],
        "tags": [t for t in (d.get("tags") or []) if isinstance(t, str)],
        "vulns": sorted({v for v in (vulns or []) if isinstance(v, str)}),
        "services": services,
    }


def collect(session) -> list[dict]:
    """Query Shodan for every resolved public IP in the session.

    Returns a list of normalized host records (only IPs Shodan has data for).
    Always returns a list; never raises.
    """
    ips = _session_ips(session)
    if not ips:
        logger.info("[shodan:%s] no resolved public IPs — skipping", session.id)
        return []

    key = getattr(settings, "SHODAN_API_KEY", "")
    results: list[dict] = []

    if key:
        cap = getattr(settings, "SHODAN_MAX_IPS", _DEFAULT_MAX_IPS)
        if cap and len(ips) > cap:
            logger.warning(
                "[shodan:%s] capping %d IPs to %d for the paid host API "
                "(SHODAN_MAX_IPS); %d IP(s) not queried this run",
                session.id, len(ips), cap, len(ips) - cap,
            )
            ips = ips[:cap]
        for ip in ips:
            data = _get_json(f"{_HOST_API_URL}/{ip}", params={"key": key})
            if data:
                results.append(_normalize_host(ip, data))
        tier = "host API (keyed)"
    else:
        # Free InternetDB path — no key, no credits. The upgrade prompt is a
        # one-time info log so keyless operators know richer output is available.
        logger.info(
            "[shodan:%s] no SHODAN_API_KEY set — using the free InternetDB tier "
            "(set a key for service banners + versions)", session.id,
        )
        for ip in ips:
            data = _get_json(f"{_INTERNETDB_URL}/{ip}")
            if data:
                results.append(_normalize_internetdb(ip, data))
        tier = "InternetDB (free)"

    logger.info(
        "[shodan:%s] queried %d IP(s) via %s — %d with exposure data",
        session.id, len(ips), tier, len(results),
    )
    return results
