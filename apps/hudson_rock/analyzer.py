"""Hudson Rock analyzer — builds a single aggregate infostealer-exposure Finding.

Privacy contract (hard requirement): this tool must NEVER store or display
plaintext credentials or individual email addresses. Only aggregate counts,
stealer-family names, last-seen dates, and system-level affected login URLs are
persisted. If a Cavalier response ever carries per-person data, it is dropped
here — only the fields explicitly extracted below reach the Finding.
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_MAX_URLS = 10  # cap the affected-URL list stored / shown
_MAX_FAMILIES = 5  # cap the top stealer families shown
_ATTRIBUTION = "Source: Hudson Rock (Cavalier)"


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _extract_urls(urls_raw) -> list[str]:
    """Pull system-level login URL strings out of the urls-by-domain payload.

    Defensive: the endpoint may return a bare list of strings, a list of dicts
    with a "url" key, or a dict wrapping the list under "data"/"urls". Only the
    URL string itself is kept — no other per-record fields are ever read, so no
    credential/email field can leak through.
    """
    if isinstance(urls_raw, dict):
        urls_raw = urls_raw.get("data") or urls_raw.get("urls") or []

    if not isinstance(urls_raw, list):
        return []

    seen: set[str] = set()
    out: list[str] = []
    for item in urls_raw:
        url = None
        if isinstance(item, str):
            url = item.strip()
        elif isinstance(item, dict):
            candidate = item.get("url")
            if isinstance(candidate, str):
                url = candidate.strip()
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _top_families(families) -> list[str]:
    """Return top stealer-family names by count (names only, no counts leaked)."""
    if not isinstance(families, dict):
        return []
    ordered = sorted(
        families.items(),
        key=lambda kv: _as_int(kv[1]),
        reverse=True,
    )
    return [str(name) for name, _ in ordered[:_MAX_FAMILIES] if name]


def _most_recent(*dates) -> str:
    """Pick the most recent (lexically max, ISO dates) non-empty date string."""
    valid = [str(d) for d in dates if d]
    return max(valid) if valid else ""


def analyze(session, domain: str, data: dict) -> list[Finding]:
    counts = data.get("counts") or {}
    employees = _as_int(counts.get("employees"))
    users = _as_int(counts.get("users"))
    third_parties = _as_int(counts.get("third_parties"))

    # No exposure → no finding.
    if employees == 0 and users == 0:
        logger.info("hudson_rock: %s has no employee/user exposure — no finding", domain)
        return []

    severity = "high" if employees > 0 else "medium"

    families = _top_families(counts.get("stealerFamilies"))
    last_compromised = _most_recent(
        counts.get("last_employee_compromised"),
        counts.get("last_user_compromised"),
    )
    affected_urls = _extract_urls(data.get("urls"))[:_MAX_URLS]

    title = (
        f"Infostealer exposure: {employees} employee + {users} user "
        f"accounts for {domain}"
    )

    lines = [
        f"Hudson Rock's Cavalier dataset shows infostealer-log exposure for "
        f"{domain}. Devices infected by info-stealing malware had credentials "
        f"harvested and traded; the counts below are the accounts tied to this "
        f"domain.",
        "",
        f"Employee accounts compromised: {employees}",
        f"Other/user accounts compromised: {users}",
        f"Third-party accounts compromised: {third_parties}",
    ]
    if families:
        lines.append(f"Top stealer families: {', '.join(families)}")
    if last_compromised:
        lines.append(f"Most recent compromise seen: {last_compromised}")
    if affected_urls:
        lines.append("")
        lines.append("Affected login URLs (system-level):")
        lines.extend(f"  - {u}" for u in affected_urls)
    lines.append("")
    lines.append(
        "These are aggregate counts only — no plaintext credentials are stored "
        "or shown here. Retrieving the specific affected accounts requires your "
        "own follow-up with Hudson Rock."
    )
    lines.append(_ATTRIBUTION)

    remediation = (
        "Force a credential reset on the affected services for the exposed "
        "accounts and enforce MFA everywhere. Treat the affected hosts as "
        "potentially compromised: investigate the endpoints the credentials "
        "came from for active info-stealer infections and re-image if needed."
    )

    finding = Finding(
        session=session,
        source="hudson_rock",
        check_type="infostealer_exposure",
        severity=severity,
        title=title,
        description="\n".join(lines),
        remediation=remediation,
        target=domain,
        extra={
            "employees": employees,
            "users": users,
            "third_parties": third_parties,
            "stealer_families": families,
            "last_compromised": last_compromised,
            "affected_urls": affected_urls,
        },
    )
    return [finding]
