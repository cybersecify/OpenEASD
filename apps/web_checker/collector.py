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

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning from verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 10  # seconds
USER_AGENT = "openeasd-web-checker/1.0"
BODY_SNIPPET_SIZE = 4096  # chars to read for directory listing check
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
    from apps.core.assets.models import URL

    urls = list(URL.objects.filter(session=session).select_related("port", "subdomain"))
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
                verify=False,
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
