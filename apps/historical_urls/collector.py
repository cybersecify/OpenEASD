"""Historical URL collector — runs gau per subdomain.

gau accepts a domain as a positional argument and emits one URL per line to
stdout. It needs no credentials or special setup beyond being on PATH (or
configured via TOOL_GAU in settings), and pulls from the Wayback Machine,
Common Crawl, AlienVault OTX, and URLScan.

gau CLI:       gau <domain>
"""

import logging
import shutil
import subprocess

from django.conf import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 300  # seconds per tool per domain


def _run_tool(binary: str, domain: str, timeout: int = _TIMEOUT) -> list[str]:
    """Run a single URL history tool against one domain.

    Returns a list of URL strings (one per stdout line). Returns [] on any
    error — missing binary, non-zero exit, timeout.
    """
    if not shutil.which(binary):
        logger.debug("binary not found at %r — skipping", binary)
        return []

    try:
        result = subprocess.run(
            [binary, domain],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        logger.warning("%s timed out after %ss on %s", binary, timeout, domain)
        return []
    except FileNotFoundError:
        logger.warning("binary %r not found during subprocess call", binary)
        return []

    if result.returncode != 0:
        logger.warning(
            "%s exited %s on %s: %s",
            binary, result.returncode, domain, (result.stderr or "")[:200],
        )
        return []

    return [line for line in result.stdout.splitlines() if line.strip()]


def collect(subdomains: list[str]) -> list[str]:
    """Run gau against every subdomain; return deduplicated URL strings.

    gau pulls from the Wayback Machine, Common Crawl, AlienVault OTX, and URLScan
    — a superset of what waybackurls covered — so it is the single historical-URL
    source. (waybackurls was dropped: it ships without a declared license, and gau
    already covers its one source, the Wayback Machine.)
    """
    if not subdomains:
        return []

    seen: set[str] = set()
    results: list[str] = []

    for domain in subdomains:
        binary = getattr(settings, "TOOL_GAU", "gau")
        for url in _run_tool(binary, domain):
            if url not in seen:
                seen.add(url)
                results.append(url)

    logger.info(
        "[historical_urls] collected %d unique URLs from %d subdomains",
        len(results), len(subdomains),
    )
    return results
