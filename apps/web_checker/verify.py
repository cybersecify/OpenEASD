"""Re-probe verifier for web_checker findings.

Re-fetches the target URL's response headers and checks whether the specific
gap the finding recorded still holds. Active (touches the target) — gated
upstream by DomainAuthorization in verify_session, same as the tool itself.

Real finding shape (confirmed by reading analyzer.py, not assumed): a
missing-security-header finding does NOT use check_type == "missing_header".
``analyzer._security_header_findings`` emits one of check_type in
{missing_csp, missing_xfo, missing_xcto, missing_permissions_policy,
missing_referrer_policy}, and ``analyzer._hsts_findings`` emits
check_type="missing_hsts" for the "no HSTS at all" case. All of these share
the same extra shape: ``extra={"header": "<Header-Name>", "url": ...}`` — the
absent header's canonical name lives in ``extra["header"]`` regardless of
which specific check_type produced the finding, so keying off ``extra["header"]``
(as long as check_type is in the known missing-header family) covers every
one of them without a per-check_type table.

Every other web_checker check_type — weak_hsts (header present but weak, a
different question than "is it missing"), cookie_missing_* (extra has no
"header" key), cors_* , server_*_disclosure, directory_listing, and
*_security_txt — has no re-probe rule in this seed verifier and returns an
honest INCONCLUSIVE rather than a guess.

No standalone single-URL "fetch headers" helper exists in collector.py to
import — collector.collect() fetches all of a session's URLs in one loop
(headers + cookies + body + CORS-reflection probe together) and isn't
callable for a single re-probe. ``_fetch_headers`` below is a new, minimal
function, but it reuses collector.py's own request conventions (REQUEST_TIMEOUT,
USER_AGENT, verify=False for target hosts with self-signed certs) rather than
inventing new ones, and stays a thin, directly patchable wrapper for tests.
"""
import requests

from apps.core.engine.verification.verdict import Verdict
from apps.web_checker.collector import REQUEST_TIMEOUT, USER_AGENT

# check_types for which extra["header"] names a security header this verifier
# knows how to re-probe by simple presence/absence.
_MISSING_HEADER_CHECK_TYPES = {
    "missing_csp",
    "missing_xfo",
    "missing_xcto",
    "missing_permissions_policy",
    "missing_referrer_policy",
    "missing_hsts",
}


def _fetch_headers(url: str) -> dict:
    """Fetch response headers for ``url``, lowercase-keyed for case-insensitive lookup."""
    resp = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        verify=False,  # nosec B501 — matches collector.py: target hosts may have self-signed certs
        allow_redirects=True,
    )
    return {k.lower(): v for k, v in resp.headers.items()}


def verify_finding(finding) -> Verdict:
    """Re-probe a single web_checker finding.

    Only the "missing security header" family has a re-probe rule here; every
    other check_type is honestly INCONCLUSIVE (no re-probe rule yet), never a
    guessed result.
    """
    header = (finding.extra or {}).get("header", "")

    if finding.check_type not in _MISSING_HEADER_CHECK_TYPES or not header:
        return Verdict(Verdict.INCONCLUSIVE, detail=f"no re-probe rule for {finding.check_type}")

    url = finding.target if finding.target.startswith("http") else f"https://{finding.target}"
    try:
        headers = _fetch_headers(url)
    except Exception as exc:  # noqa: BLE001 — any fetch failure -> inconclusive, never raise
        return Verdict(Verdict.INCONCLUSIVE, detail=f"fetch failed: {exc}")

    # A "missing header" finding is verified only if it is STILL missing.
    if header.lower() in headers:
        return Verdict(
            Verdict.INCONCLUSIVE,
            detail=f"{header} now present",
            evidence=headers.get(header.lower(), ""),
        )
    return Verdict(
        Verdict.VERIFIED,
        evidence=f"{header} still absent (headers seen: {sorted(headers)[:8]})",
    )
