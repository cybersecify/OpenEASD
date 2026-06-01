"""Historical URL collector — runs gau + waybackurls per subdomain.

Both tools accept a domain as a positional argument and emit one URL per
line to stdout. Neither needs credentials or special setup beyond being on
PATH (or configured via TOOL_GAU / TOOL_WAYBACKURLS in settings).

gau CLI:       gau <domain>
waybackurls:   waybackurls <domain>
"""

import logging
import shutil
import subprocess

from django.conf import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 300  # seconds per tool per domain


def _run_tool(binary_setting_key: str, domain: str, timeout: int = _TIMEOUT) -> list[str]:
    """Run a single URL history tool against one domain.

    Returns a list of URL strings (one per stdout line). Returns [] on any
    error — missing binary, non-zero exit, timeout.
    """
    binary = getattr(settings, binary_setting_key, binary_setting_key.replace("TOOL_", "").lower())

    if not shutil.which(binary):
        logger.debug("%s binary not found at %r — skipping", binary_setting_key, binary)
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

    if result.returncode != 0:
        logger.warning(
            "%s exited %s on %s: %s",
            binary, result.returncode, domain, (result.stderr or "")[:200],
        )
        return []

    return [line for line in result.stdout.splitlines() if line.strip()]


def collect(subdomains: list[str]) -> list[str]:
    """Run gau + waybackurls against every subdomain; return deduplicated URL strings.

    Both tools are optional — if either binary is missing the other still runs.
    """
    if not subdomains:
        return []

    seen: set[str] = set()
    results: list[str] = []

    for domain in subdomains:
        for tool_key in ("TOOL_GAU", "TOOL_WAYBACKURLS"):
            for url in _run_tool(tool_key, domain):
                if url not in seen:
                    seen.add(url)
                    results.append(url)

    logger.info(
        "[historical_urls] collected %d unique URLs from %d subdomains",
        len(results), len(subdomains),
    )
    return results
