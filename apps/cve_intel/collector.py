"""Network layer for CVE Intel — fetches CISA KEV + EPSS scores.

No DB access here. Every function degrades to an empty result on any network
or parse failure so enrichment never fails the scan.
"""

import logging

import requests
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

KEV_CACHE_KEY = "cve_intel:kev_catalog"
KEV_CACHE_TTL = 86400          # refetch the KEV catalog at most once/day
EPSS_BATCH = 100               # CVEs per EPSS request (keep the query string sane)


def _timeout() -> int:
    return int(getattr(settings, "SCANNER_HTTP_TIMEOUT", 10))


def fetch_kev_catalog() -> dict:
    """Return {CVE_ID: {"date_added": str, "due_date": str}} from CISA KEV.

    Cached for KEV_CACHE_TTL. Returns {} on any failure (caller enriches with
    cisa_kev=False rather than crashing).
    """
    cached = cache.get(KEV_CACHE_KEY)
    if cached is not None:
        return cached

    http_timeout = _timeout()
    try:
        resp = requests.get(KEV_URL, timeout=http_timeout)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        logger.warning("[cve_intel] KEV fetch failed: %s", e)
        return {}

    catalog = {}
    for item in data.get("vulnerabilities", []):
        cve = (item.get("cveID") or "").strip().upper()
        if cve:
            catalog[cve] = {
                "date_added": item.get("dateAdded", ""),
                "due_date": item.get("dueDate", ""),
            }
    cache.set(KEV_CACHE_KEY, catalog, KEV_CACHE_TTL)
    logger.info("[cve_intel] KEV catalog loaded: %d CVEs", len(catalog))
    return catalog


def fetch_epss_scores(cves: list[str]) -> dict:
    """Return {CVE_ID: {"epss": float, "percentile": float}} for the given CVEs.

    Queries the FIRST.org EPSS API in batches. Returns partial results on
    per-batch failure (a failed batch is simply skipped).
    """
    scores: dict[str, dict] = {}
    unique = sorted({c.strip().upper() for c in cves if c})
    if not unique:
        return scores

    http_timeout = _timeout()
    for i in range(0, len(unique), EPSS_BATCH):
        batch = unique[i:i + EPSS_BATCH]
        try:
            resp = requests.get(
                EPSS_URL,
                params={"cve": ",".join(batch)},
                timeout=http_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            logger.warning("[cve_intel] EPSS batch %d failed: %s", i // EPSS_BATCH, e)
            continue

        for row in data.get("data", []):
            cve = (row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                scores[cve] = {
                    "epss": float(row.get("epss", 0.0)),
                    "percentile": float(row.get("percentile", 0.0)),
                }
            except (TypeError, ValueError):
                continue

    logger.info("[cve_intel] EPSS scored %d/%d CVEs", len(scores), len(unique))
    return scores
