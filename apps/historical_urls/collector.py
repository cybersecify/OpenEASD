"""Historical URL discovery — runs gau and/or waybackurls against subdomains.

Pulls historical URLs from Wayback Machine, AlienVault OTX, Common Crawl,
and URLScan.io. Surfaces forgotten endpoints, deprecated APIs, and
removed-but-still-deployed paths that current crawling misses.
"""

import logging
import subprocess
import shutil

from django.conf import settings

logger = logging.getLogger(__name__)

# Extensions to skip (images, fonts, media, documents)
SKIP_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp", ".avif",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Media
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".ogg",
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    # Archives
    ".zip", ".tar", ".gz", ".rar", ".7z",
    # Other
    ".css", ".js", ".map",
}


def _run_gau(domain: str) -> list[str]:
    """Run gau against a domain and return discovered URLs."""
    binary = getattr(settings, "TOOL_GAU", "gau")

    if not shutil.which(binary):
        logger.warning(f"gau binary not found at '{binary}', skipping gau")
        return []

    try:
        result = subprocess.run(
            [binary, "--subs", "--threads", "5", domain],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            logger.warning(f"gau failed for {domain}: {result.stderr[:200]}")
            return []

        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"gau found {len(urls)} URLs for {domain}")
        return urls

    except subprocess.TimeoutExpired:
        logger.warning(f"gau timed out for {domain}")
        return []
    except Exception as e:
        logger.error(f"gau error for {domain}: {e}")
        return []


def _run_waybackurls(domain: str) -> list[str]:
    """Run waybackurls against a domain and return discovered URLs."""
    binary = getattr(settings, "TOOL_WAYBACKURLS", "waybackurls")

    if not shutil.which(binary):
        logger.warning(f"waybackurls binary not found at '{binary}', skipping waybackurls")
        return []

    try:
        result = subprocess.run(
            [binary, "--no-subs", domain],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            logger.warning(f"waybackurls failed for {domain}: {result.stderr[:200]}")
            return []

        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"waybackurls found {len(urls)} URLs for {domain}")
        return urls

    except subprocess.TimeoutExpired:
        logger.warning(f"waybackurls timed out for {domain}")
        return []
    except Exception as e:
        logger.error(f"waybackurls error for {domain}: {e}")
        return []


def collect(session, domains: list[str]) -> list[str]:
    """
    Run gau and waybackurls against a list of domains. Returns deduplicated URLs.

    Args:
        session: The scan session object
        domains: List of domain names to query

    Returns:
        Deduplicated list of discovered URLs
    """
    if not domains:
        return []

    all_urls = set()

    for domain in domains:
        # Run both tools and merge results
        gau_urls = _run_gau(domain)
        wayback_urls = _run_waybackurls(domain)

        all_urls.update(gau_urls)
        all_urls.update(wayback_urls)

    # Filter out URLs with skip extensions
    filtered_urls = []
    for url in all_urls:
        # Extract path and check extension
        path = url.split("?")[0].split("#")[0].lower()
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            continue
        filtered_urls.append(url)

    logger.info(
        f"[historical_urls:{session.id}] "
        f"Discovered {len(filtered_urls)} URLs from {len(domains)} domains "
        f"(filtered from {len(all_urls)} total)"
    )

    return filtered_urls
