"""Web Checker — inspects HTTP responses for security header and config issues.

Checks:
  - Missing security headers (CSP, X-Frame-Options, etc.)
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - CORS misconfiguration (wildcard, origin reflection)
  - Server version disclosure (Server, X-Powered-By headers)
  - Directory listing (open indexes)

Uses the requests library to fetch each URL discovered by httpx.
"""

import logging
import re

import requests
import urllib3
from django.conf import settings

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning from verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 10  # seconds
# Honest scanner identity — use the shared UA so a target can allowlist us, same
# as httpx/katana/nuclei (was a tool-specific string; the only tool that diverged).
USER_AGENT = getattr(
    settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0 (+https://cybersecify.com/openeasd)"
)
BODY_SNIPPET_SIZE = 4096  # chars to read for directory listing check
SECURITY_TXT_MAX = 8192  # chars to read from a security.txt response
_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Test origin for CORS reflection check
_CORS_TEST_ORIGIN = "https://evil.example.com"


def _parse_cookies(response) -> list[dict]:
    """Parse Set-Cookie headers for security flag analysis."""
    cookies = []
    # response.headers is case-insensitive but only returns one value per key;
    # use raw headers to get all Set-Cookie lines
    raw_headers = response.raw.headers if response.raw else {}
    set_cookie_headers = raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []

    # Fallback: if raw headers not available, use response.cookies
    if not set_cookie_headers and response.cookies:
        for cookie in response.cookies:
            cookies.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": bool(cookie._rest.get("HttpOnly") or cookie._rest.get("httponly")),
                "samesite": None,  # can't reliably get from requests.cookies
            })
        return cookies

    for header_val in set_cookie_headers:
        lower = header_val.lower()
        # Extract cookie name (before first =)
        name = header_val.split("=", 1)[0].strip() if "=" in header_val else ""
        cookies.append({
            "name": name,
            "secure": "; secure" in lower or ";secure" in lower,
            "httponly": "; httponly" in lower or ";httponly" in lower,
            "samesite": _parse_samesite(lower),
        })
    return cookies


def _parse_samesite(lower_header: str) -> str | None:
    """Extract SameSite value from lowercase Set-Cookie header."""
    match = re.search(r";\s*samesite\s*=\s*(\w+)", lower_header)
    return match.group(1).capitalize() if match else None


def _extract_title(body: str) -> str:
    """Extract <title> content from HTML body snippet."""
    match = _TITLE_RE.search(body)
    return match.group(1).strip() if match else ""


def collect(session) -> list[dict]:
    """
    Fetch all web URLs and return response metadata for security analysis.

    Returns one result dict per URL:
      {
        url, url_fk, port_fk, host, status_code,
        headers: dict,
        cookies: list[dict],
        body_snippet: str,
        title: str,
        cors_reflects_origin: bool,
        error: str | None,
      }
    """
    from apps.core.data.web_assets.models import URL

    # Deduplicate to one representative URL per (host, port_number).
    # Security headers and cookies are server-wide — checking 50 katana-crawled
    # paths on the same host would produce 50 identical findings and 50× the
    # HTTP requests. httpx URLs (ordered first) are the canonical root URLs.
    all_urls = URL.objects.filter(session=session).select_related(
        "port", "subdomain"
    ).order_by("source")  # "httpx" < "katana" alphabetically → httpx wins
    seen_hosts: set[tuple] = set()
    urls = []
    for u in all_urls:
        key = (u.host, u.port_number)
        if key not in seen_hosts:
            seen_hosts.add(key)
            urls.append(u)

    if not urls:
        logger.info(f"[web_checker:{session.id}] No URLs to check")
        return []

    results = []
    for url_obj in urls:
        target = url_obj.url
        logger.debug(f"[web_checker:{session.id}] Checking {target}")

        try:
            resp = requests.get(
                target,
                timeout=REQUEST_TIMEOUT,
                headers={
                    "User-Agent": USER_AGENT,
                    "Origin": _CORS_TEST_ORIGIN,
                },
                verify=False,  # nosec B501 — intentional: scanning target hosts that may have self-signed certs
                allow_redirects=True,
            )

            body = resp.text[:BODY_SNIPPET_SIZE] if resp.text else ""
            headers = dict(resp.headers)

            # Check CORS origin reflection
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            cors_reflects = acao == _CORS_TEST_ORIGIN

            results.append({
                "url": target,
                "url_fk": url_obj,
                "port_fk": url_obj.port,
                "host": url_obj.host,
                "status_code": resp.status_code,
                "headers": headers,
                "cookies": _parse_cookies(resp),
                "body_snippet": body,
                "title": _extract_title(body),
                "cors_reflects_origin": cors_reflects,
                "error": None,
            })

        except requests.RequestException as e:
            logger.warning(f"[web_checker:{session.id}] Failed to fetch {target}: {e}")
            results.append({
                "url": target,
                "url_fk": url_obj,
                "port_fk": url_obj.port,
                "host": url_obj.host,
                "status_code": 0,
                "headers": {},
                "cookies": [],
                "body_snippet": "",
                "title": "",
                "cors_reflects_origin": False,
                "error": str(e),
            })

    logger.info(
        f"[web_checker:{session.id}] Fetched {len(results)} URLs, "
        f"{sum(1 for r in results if r['error'])} errors"
    )
    return results


def _looks_like_security_txt(status_code: int, body: str) -> bool:
    """A real security.txt is text with a Contact: field (RFC 9116). Guards
    against SPA catch-alls / soft-404s that answer 200 with an HTML page for
    any path — those have no Contact: line and are HTML, so they're rejected."""
    if status_code != 200 or not body:
        return False
    head = body[:512].lower()
    if "<html" in head or "<!doctype html" in head:
        return False
    return "contact:" in body.lower()


def collect_security_txt(session) -> dict | None:
    """Fetch /.well-known/security.txt (RFC 9116) for the scan's primary domain.

    security.txt is a host-wide, domain-root policy — researchers look for it on
    the apex (or www), not on every discovered subdomain — so this checks only
    the apex/www web origin (prefer HTTPS, prefer apex) and runs at most once per
    scan. Returns ``None`` when the apex has no probed web URL (we didn't reach a
    web root, so there's nothing to assert). Fail-graceful: a fetch error yields a
    result with ``found=False`` and the error, never an exception.

    Result dict: ``{host, url_fk, port_fk, found, location, raw, error}``.
    """
    from apps.core.data.web_assets.models import URL

    domain = (session.domain or "").strip().lower()
    if not domain:
        return None

    candidates = list(
        URL.objects.filter(session=session, host__in=[domain, f"www.{domain}"])
        .select_related("port")
    )
    if not candidates:
        return None

    # Prefer an HTTPS origin, then the bare apex over www.
    def _rank(u):
        return (0 if u.url.startswith("https://") else 1, 0 if u.host == domain else 1)

    best = sorted(candidates, key=_rank)[0]
    scheme = "https" if best.url.startswith("https://") else "http"
    base = f"{scheme}://{best.host}"

    # Certificate validation stays ON here (unlike the target-probing fetches
    # above): a security.txt served over an untrusted cert isn't trustworthy, and
    # the apex of a real org has valid TLS. A TLS/connection failure means we
    # COULDN'T check (reachable=False) — the analyzer then reports nothing rather
    # than a false "missing", keeping the scanner honest (tls_checker owns the
    # cert finding).
    found, reachable, location, raw, error = False, False, None, "", None
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            resp = requests.get(
                base + path,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
            )
            reachable = True
            body = resp.text[:SECURITY_TXT_MAX] if resp.text else ""
            if _looks_like_security_txt(resp.status_code, body):
                found, location, raw = True, base + path, body
                break
        except requests.RequestException as e:
            error = str(e)
            logger.warning(f"[web_checker:{session.id}] security.txt fetch failed for {base + path}: {e}")

    logger.info(
        f"[web_checker:{session.id}] security.txt for {best.host}: "
        f"{'found' if found else ('not found' if reachable else 'unreachable')}"
    )
    return {
        "host": best.host,
        "url_fk": best,
        "port_fk": best.port,
        "found": found,
        "reachable": reachable,
        "location": location,
        "raw": raw,
        "error": error,
    }
