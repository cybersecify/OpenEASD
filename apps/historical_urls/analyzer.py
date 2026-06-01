"""Historical URL analyzer — parse URLs and create URL records."""

import logging
from urllib.parse import urlparse

from django.db import transaction

from apps.core.assets.models import Subdomain
from apps.core.web_assets.models import URL

logger = logging.getLogger(__name__)


def _extract_scheme_host_port(url: str) -> tuple[str, str, int]:
    """Extract scheme, host, and port from a URL."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or ""

    # Determine port
    if parsed.port:
        port = parsed.port
    elif scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        port = 443

    return scheme, host, port


def analyze(session, urls: list[str]) -> list[URL]:
    """
    Parse discovered URLs and create URL model instances.

    Links each URL to its corresponding Subdomain record if it exists in the DB.

    Args:
        session: The scan session object
        urls: List of URL strings from gau/waybackurls

    Returns:
        List of URL model instances ready for bulk_create
    """
    if not urls:
        return []

    # Get all subdomains for this session for lookup
    subdomains = {
        s.subdomain: s
        for s in Subdomain.objects.filter(session=session)
    }

    objs = []
    seen = set()

    for url_str in urls:
        try:
            scheme, host, port = _extract_scheme_host_port(url_str)

            # Skip if we've already seen this URL
            normalized = f"{scheme}://{host}:{port}{urlparse(url_str).path}"
            if normalized in seen:
                continue
            seen.add(normalized)

            # Find matching subdomain
            subdomain = subdomains.get(host)

            # Create URL instance
            obj = URL(
                session=session,
                url=url_str,
                scheme=scheme,
                host=host,
                port=port,
                path=urlparse(url_str).path or "/",
                source="historical_urls",
                status_code=None,  # Will be probed later by httpx/katana
                subdomain=subdomain,
            )
            objs.append(obj)

        except Exception as e:
            logger.warning(f"Failed to parse URL '{url_str}': {e}")
            continue

    logger.info(
        f"[historical_urls:{session.id}] "
        f"Analyzed {len(urls)} URLs → {len(objs)} unique URL records"
    )

    return objs
