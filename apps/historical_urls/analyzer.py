"""Historical URL analyzer — filters noise, builds URL asset objects.

Noise filtering removes URLs pointing at binary/static assets that have no
security relevance (images, fonts, stylesheets, archives). This reduces
the URL pool fed to downstream tools (nuclei, web_checker) without hiding
any interesting endpoints.
"""

import logging
from urllib.parse import urlparse

from apps.core.assets.models import Subdomain
from apps.core.web_assets.models import URL

logger = logging.getLogger(__name__)

_NOISE_EXTENSIONS = frozenset([
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
    # Fonts
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    # Stylesheets
    ".css",
    # Archives / executables
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".exe", ".dmg", ".pkg",
    # Media
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".ogg", ".flac",
])

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _is_noise(url: str) -> bool:
    """Return True if the URL points at a non-interesting static asset."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return True
    dot = path.rfind(".")
    if dot != -1:
        ext = path[dot:]
        ext = ext.split("?")[0].split("#")[0]
        return ext in _NOISE_EXTENSIONS
    return False


def analyze(session, raw_urls: list[str]) -> list[URL]:
    """Filter noise and build URL asset objects from raw URL strings.

    FK lookups:
    - port: resolved from existing httpx URL rows (host + port_number match)
    - subdomain: resolved from session Subdomain rows (hostname match)
    """
    if not raw_urls:
        return []

    # Build lookup maps from httpx URL rows already in the session
    httpx_urls = URL.objects.filter(session=session, source="httpx").select_related("port", "subdomain")
    port_map: dict[tuple[str, int], object] = {}
    sub_map: dict[str, object] = {}
    for u in httpx_urls:
        if u.host and u.port_number is not None:
            port_map[(u.host, u.port_number)] = u.port
        if u.subdomain and u.host:
            sub_map[u.host] = u.subdomain

    # Supplement subdomain map from session subdomains
    for s in Subdomain.objects.filter(session=session):
        if s.subdomain not in sub_map:
            sub_map[s.subdomain] = s

    objs: list[URL] = []
    seen: set[str] = set()

    for raw in raw_urls:
        url_str = raw.strip()
        if not url_str or url_str in seen:
            continue
        if _is_noise(url_str):
            continue

        parsed = urlparse(url_str)
        scheme = parsed.scheme
        host = parsed.hostname or ""
        if not host or not scheme:
            continue

        seen.add(url_str)

        port_num = parsed.port or _DEFAULT_PORTS.get(scheme)
        port_fk = port_map.get((host, port_num)) if port_num else None
        sub_fk = sub_map.get(host)

        objs.append(URL(
            session=session,
            port=port_fk,
            subdomain=sub_fk,
            url=url_str,
            scheme=scheme,
            host=host,
            port_number=port_num,
            source="historical_urls",
        ))

    logger.info(
        "[historical_urls:%s] %d raw URLs → %d after noise filter",
        session.id, len(raw_urls), len(objs),
    )
    return objs
