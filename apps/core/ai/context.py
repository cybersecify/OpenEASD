"""Prompt-context builders — read-only, no writes, cheap to unit test.

Everything the LLM sees is assembled here, so what leaves the box is
reviewable in one place. Descriptions are truncated hard: prompts carry the
minimum needed to rank, not full report bodies.
"""

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_DESCRIPTION_CHARS = 300

_SYSTEM_PROMPT = (
    "You are the analyst layer of OpenEASD, an external attack-surface scanner. "
    "You receive security findings from one scan of one domain as JSON. "
    "Be precise and sceptical: scanners overreport, and your job is to say what "
    "actually matters on this surface and why. Reply with only the requested "
    "JSON object — no prose outside it."
)


def severity_counts(session) -> dict:
    from apps.core.findings.models import Finding

    counts = {s: 0 for s in _SEVERITY_ORDER}
    for row in Finding.objects.filter(session=session).values_list("severity", flat=True):
        if row in counts:
            counts[row] += 1
    return counts


def select_findings(session, cap: int) -> list:
    """Severity-ranked selection, stable by id, capped at `cap`.

    Info findings are excluded — they are context noise for ranking and eat
    prompt budget.
    """
    from apps.core.findings.models import Finding

    findings = list(
        Finding.objects.filter(session=session)
        .exclude(severity="info")
        .select_related("port", "url")
    )
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.id))
    return findings[: max(cap, 0)]


def finding_brief(finding) -> dict:
    """Compact, prompt-safe view of one Finding."""
    extra = finding.extra or {}
    brief = {
        "id": finding.id,
        "severity": finding.severity,
        "source": finding.source,
        "check_type": finding.check_type,
        "title": finding.title[:200],
        "target": finding.target,
        "description": (finding.description or "")[:_MAX_DESCRIPTION_CHARS],
    }
    for key in ("cve", "cvss_score", "epss_score", "kev", "service", "version", "port_number"):
        if extra.get(key) not in (None, "", []):
            brief[key] = extra[key]
    return brief


def scan_facts(session) -> dict:
    """Non-finding context: what was scanned and how well it was reached."""
    return {
        "domain": session.domain,
        "severity_counts": severity_counts(session),
        "total_findings": session.total_findings,
        "endpoints_probed": session.endpoints_probed,
        "endpoints_blocked": session.endpoints_blocked,
        "waf_vendor": session.waf_vendor or None,
        "scan_status": session.status,
    }


def build_triage_messages(session, findings: list) -> list[dict]:
    import json

    payload = {
        "scan": scan_facts(session),
        "findings": [finding_brief(f) for f in findings],
    }
    instructions = (
        "Triage these findings. Return JSON with:\n"
        "- overview: 3-6 sentences a security engineer would write about this "
        "attack surface — what stands out, what is probably noise, and the single "
        "most important next step.\n"
        "- items: the findings re-ranked by real-world exploitability and impact "
        "(most urgent first). For each: its finding_id (must be one of the given "
        "ids), a priority of fix_now/plan/monitor/likely_noise, and a 1-2 sentence "
        "rationale grounded in the finding's own data (CVE/EPSS/KEV, exposure, "
        "service). Include every given finding exactly once."
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": instructions + "\n\n" + json.dumps(payload)},
    ]


def build_summary_messages(session, kind: str, triage_overview: str = "") -> list[dict]:
    import json

    payload = {"scan": scan_facts(session)}
    if triage_overview:
        payload["analyst_overview"] = triage_overview

    if kind == "alert":
        instructions = (
            "Write the `text` for a chat alert about this scan: at most 2 plain "
            "sentences, no markdown, leading with the most urgent point. If "
            "nothing is urgent, say the surface looks stable."
        )
    else:
        instructions = (
            "Write the `text` for a PDF report's executive summary about this "
            "scan: one paragraph (4-6 sentences), plain language for a technical "
            "manager, covering overall risk, what stands out, and the recommended "
            "next step. No markdown."
        )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": instructions + "\n\n" + json.dumps(payload)},
    ]
