"""Web Checker analyzer — converts HTTP response data into Finding objects.

Finding categories:
  - Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - CORS misconfiguration (wildcard, origin reflection)
  - Server version disclosure (Server, X-Powered-By headers)
  - Directory listing detection
"""

import logging
import re

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security header checks
# ---------------------------------------------------------------------------

# (header_name, check_type, severity, description, remediation)
_HEADER_CHECKS = [
    (
        "Content-Security-Policy",
        "missing_csp",
        "high",
        "Without CSP, the browser has no restrictions on inline scripts, eval(), "
        "or resource origins — enabling XSS attacks to execute arbitrary JavaScript.",
        "Add a Content-Security-Policy header. Start with a report-only policy:\n"
        "  Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; report-uri /csp-report\n"
        "Then tighten and enforce once violations are reviewed.",
    ),
    (
        "X-Frame-Options",
        "missing_xfo",
        "medium",
        "Without X-Frame-Options, attackers can embed this page in an iframe "
        "on a malicious site and perform clickjacking attacks.",
        "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed). "
        "Also set CSP frame-ancestors directive for modern browsers.",
    ),
    (
        "X-Content-Type-Options",
        "missing_xcto",
        "medium",
        "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses "
        "and interpret non-executable content as scripts, enabling XSS.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "Permissions-Policy",
        "missing_permissions_policy",
        "low",
        "Without Permissions-Policy (formerly Feature-Policy), the page can access "
        "sensitive browser APIs (camera, microphone, geolocation) by default.",
        "Add a Permissions-Policy header restricting unused APIs:\n"
        "  Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
    (
        "Referrer-Policy",
        "missing_referrer_policy",
        "low",
        "Without Referrer-Policy, the full URL (including query parameters and paths) "
        "may be leaked to third-party sites via the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy)",
    ),
]


def _security_header_findings(result: dict, session) -> list[Finding]:
    """Return findings for missing security headers."""
    if result.get("error"):
        return []

    headers = result.get("headers", {})
    # Case-insensitive header lookup
    header_names = {k.lower(): k for k in headers}
    url = result["url"]
    findings = []

    for header_name, check_type, severity, description, remediation in _HEADER_CHECKS:
        if header_name.lower() not in header_names:
            findings.append(Finding(
                session=session,
                source="web_checker",
                check_type=check_type,
                severity=severity,
                title=f"Missing {header_name} on {url}",
                description=description,
                remediation=remediation,
                url=result["url_fk"],
                port=result["port_fk"],
                target=url,
                extra={"header": header_name, "url": url},
            ))

    return findings


# ---------------------------------------------------------------------------
# Cookie security checks
# ---------------------------------------------------------------------------

def _cookie_findings(result: dict, session) -> list[Finding]:
    """Return findings for cookies missing security flags."""
    if result.get("error"):
        return []

    cookies = result.get("cookies", [])
    url = result["url"]
    is_https = url.startswith("https://")
    findings = []

    for cookie in cookies:
        name = cookie.get("name", "unknown")

        # Secure flag — only relevant for HTTPS (HTTP cookies can't be Secure)
        if is_https and not cookie.get("secure"):
            findings.append(Finding(
                session=session,
                source="web_checker",
                check_type="cookie_missing_secure",
                severity="high",
                title=f"Cookie '{name}' missing Secure flag on {url}",
                description=(
                    f"The cookie '{name}' on {url} is not marked Secure. "
                    f"It will be sent over unencrypted HTTP connections, "
                    f"exposing it to interception by network attackers."
                ),
                remediation="Set the Secure flag on all cookies served over HTTPS.",
                url=result["url_fk"],
                port=result["port_fk"],
                target=url,
                extra={"cookie_name": name, "url": url},
            ))

        if not cookie.get("httponly"):
            findings.append(Finding(
                session=session,
                source="web_checker",
                check_type="cookie_missing_httponly",
                severity="medium",
                title=f"Cookie '{name}' missing HttpOnly flag on {url}",
                description=(
                    f"The cookie '{name}' on {url} is not marked HttpOnly. "
                    f"JavaScript code (including XSS payloads) can read this cookie "
                    f"via document.cookie."
                ),
                remediation="Set the HttpOnly flag on cookies that don't need JavaScript access.",
                url=result["url_fk"],
                port=result["port_fk"],
                target=url,
                extra={"cookie_name": name, "url": url},
            ))

        if not cookie.get("samesite"):
            findings.append(Finding(
                session=session,
                source="web_checker",
                check_type="cookie_missing_samesite",
                severity="medium",
                title=f"Cookie '{name}' missing SameSite flag on {url}",
                description=(
                    f"The cookie '{name}' on {url} does not set the SameSite attribute. "
                    f"Without it, the cookie is sent on cross-site requests, enabling "
                    f"CSRF attacks. Modern browsers default to Lax, but explicit is safer."
                ),
                remediation="Set SameSite=Lax (or Strict) on all cookies.",
                url=result["url_fk"],
                port=result["port_fk"],
                target=url,
                extra={"cookie_name": name, "url": url},
            ))

    return findings


# ---------------------------------------------------------------------------
# CORS misconfiguration
# ---------------------------------------------------------------------------

def _cors_findings(result: dict, session) -> list[Finding]:
    """Return findings for CORS misconfigurations."""
    if result.get("error"):
        return []

    headers = result.get("headers", {})
    # Case-insensitive lookup
    header_lower = {k.lower(): v for k, v in headers.items()}
    acao = header_lower.get("access-control-allow-origin", "")
    credentials = header_lower.get("access-control-allow-credentials", "").lower()
    url = result["url"]

    if not acao:
        return []

    findings = []

    if acao == "*" and credentials == "true":
        findings.append(Finding(
            session=session,
            source="web_checker",
            check_type="cors_wildcard_credentials",
            severity="critical",
            title=f"CORS wildcard with credentials on {url}",
            description=(
                f"The server at {url} sets Access-Control-Allow-Origin: * with "
                f"Access-Control-Allow-Credentials: true. This is a critical "
                f"misconfiguration — any website can make authenticated cross-origin "
                f"requests and read the responses, stealing user data."
            ),
            remediation=(
                "Never combine Access-Control-Allow-Origin: * with "
                "Access-Control-Allow-Credentials: true. Whitelist specific trusted origins."
            ),
            url=result["url_fk"],
            port=result["port_fk"],
            target=url,
            extra={"acao": acao, "credentials": credentials, "url": url},
        ))
    elif result.get("cors_reflects_origin"):
        findings.append(Finding(
            session=session,
            source="web_checker",
            check_type="cors_origin_reflection",
            severity="high",
            title=f"CORS reflects arbitrary Origin on {url}",
            description=(
                f"The server at {url} reflects the Origin header value in "
                f"Access-Control-Allow-Origin without validation. Any website can "
                f"make cross-origin requests to this endpoint and read responses."
            ),
            remediation=(
                "Validate the Origin header against a whitelist of trusted origins. "
                "Do not blindly reflect the Origin value."
            ),
            url=result["url_fk"],
            port=result["port_fk"],
            target=url,
            extra={"acao": acao, "url": url},
        ))
    elif acao == "*":
        findings.append(Finding(
            session=session,
            source="web_checker",
            check_type="cors_wildcard",
            severity="medium",
            title=f"CORS wildcard Access-Control-Allow-Origin on {url}",
            description=(
                f"The server at {url} sets Access-Control-Allow-Origin: *. "
                f"Any website can make cross-origin requests. While credentials "
                f"are not included, this may expose non-public API data."
            ),
            remediation=(
                "Restrict CORS to specific trusted origins. Use a whitelist "
                "instead of the wildcard (*) value."
            ),
            url=result["url_fk"],
            port=result["port_fk"],
            target=url,
            extra={"acao": acao, "url": url},
        ))

    return findings


# ---------------------------------------------------------------------------
# Server version disclosure
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"\d+\.\d+")


def _server_disclosure_findings(result: dict, session) -> list[Finding]:
    """Return findings for server version information disclosure."""
    if result.get("error"):
        return []

    headers = result.get("headers", {})
    header_lower = {k.lower(): v for k, v in headers.items()}
    url = result["url"]
    findings = []

    server = header_lower.get("server", "")
    if server and _VERSION_RE.search(server):
        findings.append(Finding(
            session=session,
            source="web_checker",
            check_type="server_version_disclosure",
            severity="low",
            title=f"Server version disclosed on {url}",
            description=(
                f"The Server header on {url} reveals version information: '{server}'. "
                f"Attackers can use this to search for known vulnerabilities in that "
                f"specific version."
            ),
            remediation=(
                "Remove or minimize the Server header. "
                "Nginx: server_tokens off; Apache: ServerTokens Prod"
            ),
            url=result["url_fk"],
            port=result["port_fk"],
            target=url,
            extra={"server_header": server, "url": url},
        ))

    powered_by = header_lower.get("x-powered-by", "")
    if powered_by:
        findings.append(Finding(
            session=session,
            source="web_checker",
            check_type="server_poweredby_disclosure",
            severity="low",
            title=f"X-Powered-By header disclosed on {url}",
            description=(
                f"The X-Powered-By header on {url} reveals: '{powered_by}'. "
                f"This exposes the server-side technology and version, aiding "
                f"targeted attacks."
            ),
            remediation="Remove the X-Powered-By header from server responses.",
            url=result["url_fk"],
            port=result["port_fk"],
            target=url,
            extra={"powered_by": powered_by, "url": url},
        ))

    return findings


# ---------------------------------------------------------------------------
# Directory listing
# ---------------------------------------------------------------------------

def _directory_listing_findings(result: dict, session) -> list[Finding]:
    """Return a finding if the page appears to be an open directory listing."""
    if result.get("error"):
        return []

    title = result.get("title", "")
    if not title or "index of" not in title.lower():
        return []

    url = result["url"]
    return [Finding(
        session=session,
        source="web_checker",
        check_type="directory_listing",
        severity="medium",
        title=f"Directory listing enabled on {url}",
        description=(
            f"The page at {url} exposes a directory listing (title: '{title}'). "
            f"This reveals file names, directory structure, and potentially sensitive "
            f"files that should not be publicly accessible."
        ),
        remediation=(
            "Disable directory listing in your web server configuration. "
            "Nginx: autoindex off; Apache: Options -Indexes"
        ),
        url=result["url_fk"],
        port=result["port_fk"],
        target=url,
        extra={"title": title, "url": url},
    )]


# ---------------------------------------------------------------------------
# Main analyze function
# ---------------------------------------------------------------------------

def analyze(session, results: list[dict]) -> list[Finding]:
    """
    Build Finding objects from web response data.

    For each URL result, generates findings across:
      - Missing security headers
      - Cookie security flags
      - CORS misconfiguration
      - Server version disclosure
      - Directory listing
    """
    findings: list[Finding] = []

    for r in results:
        findings.extend(_security_header_findings(r, session))
        findings.extend(_cookie_findings(r, session))
        findings.extend(_cors_findings(r, session))
        findings.extend(_server_disclosure_findings(r, session))
        findings.extend(_directory_listing_findings(r, session))

    return findings
