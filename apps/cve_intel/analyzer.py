"""Pure functions: extract CVEs from a Finding and roll intel into extra.

No DB or network. Kept separate from scanner.py so it's trivially unit-testable.
"""


def finding_cves(finding) -> set[str]:
    """All CVE ids attached to a finding, uppercased.

    Handles both shapes tools write:
      - nmap:            extra["cve"]      -> single "CVE-YYYY-NNNN" string
      - nuclei/network:  extra["cve_ids"] -> list of CVE strings
    """
    extra = finding.extra or {}
    cves: set[str] = set()

    single = extra.get("cve")
    if isinstance(single, str) and single.strip():
        cves.add(single.strip().upper())

    lst = extra.get("cve_ids")
    if isinstance(lst, (list, tuple)):
        cves.update(c.strip().upper() for c in lst if isinstance(c, str) and c.strip())

    return cves


def build_finding_intel(cves: set[str], kev: dict, epss: dict) -> dict:
    """Roll per-CVE intel into a finding-level summary for sorting/filtering.

    A finding's risk is driven by its worst CVE, so:
      - epss_score / epss_percentile = the max across the finding's CVEs
      - cisa_kev = True if ANY of its CVEs is actively exploited
    Plus a per-CVE detail map so the UI can show the breakdown.

    Returns {} when none of the finding's CVEs had any intel (nothing to write).
    """
    if not cves:
        return {}

    per_cve: dict[str, dict] = {}
    max_epss = None
    max_percentile = None
    kev_hits: list[dict] = []

    for cve in sorted(cves):
        detail: dict = {}
        e = epss.get(cve)
        if e:
            detail["epss"] = e["epss"]
            detail["percentile"] = e["percentile"]
            if max_epss is None or e["epss"] > max_epss:
                max_epss = e["epss"]
                max_percentile = e["percentile"]
        k = kev.get(cve)
        detail["kev"] = k is not None
        if k:
            detail["kev_date_added"] = k.get("date_added", "")
            detail["kev_due_date"] = k.get("due_date", "")
            kev_hits.append({"cve": cve, **k})
        if detail:
            per_cve[cve] = detail

    intel: dict = {"cisa_kev": bool(kev_hits)}
    if max_epss is not None:
        intel["epss_score"] = max_epss
        intel["epss_percentile"] = max_percentile
    if kev_hits:
        intel["kev_cves"] = kev_hits
    if per_cve:
        intel["cve_intel"] = per_cve

    # Nothing useful found (no EPSS, no KEV) -> signal caller to skip the write.
    if max_epss is None and not kev_hits:
        return {}
    return intel
