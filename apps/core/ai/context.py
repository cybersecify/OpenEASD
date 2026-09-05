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
    """Compact, prompt-safe view of one Finding.

    Includes the exploit-in-the-wild signals cve_intel enriches CVE findings
    with — EPSS (probability of exploitation) and CISA KEV (known exploited) —
    under the exact keys cve_intel writes: extra["epss_score"],
    extra["epss_percentile"], extra["cisa_kev"].
    """
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
    for key in ("cve", "cvss_score", "epss_score", "epss_percentile",
                "cisa_kev", "service", "version", "port_number"):
        if extra.get(key) not in (None, "", [], False):
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
        "rationale grounded in the finding's own data. Include every given finding "
        "exactly once.\n\n"
        "RANK BY EXPLOITABILITY, NOT SEVERITY LABEL. Weight the signals in this "
        "order:\n"
        "1. cisa_kev=true — the flaw is on CISA's Known Exploited Vulnerabilities "
        "list (attackers are USING it right now). This almost always means fix_now, "
        "and it outranks a higher-CVSS finding that is not exploited. Say so in the "
        "rationale.\n"
        "2. epss_score — probability (0.0-1.0) the flaw is exploited in the next 30 "
        "days. Treat >=0.5 as strong upward pressure and >=0.1 as notable; a low "
        "epss_score (<0.01) on a high cvss_score is a sign it is likely NOT worth "
        "fix_now. epss_percentile gives the same signal ranked against all CVEs.\n"
        "3. cvss_score — theoretical severity. Use it only to break ties once the "
        "exploitation signals above are accounted for; a high CVSS with no KEV and "
        "near-zero EPSS is often plan/monitor, not fix_now.\n"
        "4. Exposure and service context (internet-facing, auth-required, etc.).\n"
        "When a finding carries no EPSS/KEV data (e.g. non-CVE findings, or CVEs "
        "the feeds don't cover), fall back to cvss_score and context — do not "
        "invent exploitation signals. Quote the actual cisa_kev/epss_score/"
        "cvss_score values you relied on in each rationale."
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": instructions + "\n\n" + json.dumps(payload)},
    ]


def tools_already_run(root_session) -> list[str]:
    """Tools executed for this scan: the root workflow run's steps plus every
    tool an earlier agent subscan already ran."""
    from apps.core.workflows.models import WorkflowStepResult

    tools = set(
        WorkflowStepResult.objects.filter(run__session=root_session)
        .exclude(status__in=("skipped",))
        .values_list("tool", flat=True)
    )
    for sub in root_session.subscans.all():
        tools.update(sub.subscan_tools or [])
    return sorted(tools)


def _tool_catalog() -> list[dict]:
    from apps.core.workflows.registry import get_registry

    return [
        {
            "name": name,
            "label": meta.get("label", name),
            "phase_group": meta.get("phase_group", ""),
            "active": meta.get("active", True),
        }
        for name, meta in sorted(get_registry().items())
        if not meta.get("core")
    ]


def _latest_agent_subscan_results(agent_run) -> dict | None:
    """Severity counts + top titles from the most recent executed agent subscan."""
    from apps.core.findings.models import Finding

    last = (
        agent_run.actions.filter(status="executed", subscan_session__isnull=False)
        .order_by("-id")
        .first()
    )
    if last is None:
        return None
    sub = last.subscan_session
    findings = list(
        Finding.objects.filter(session=sub).exclude(severity="info")
        .order_by("severity")[:20]
    )
    return {
        "tools": (sub.subscan_tools or []),
        "status": sub.status,
        "severity_counts": severity_counts(sub),
        "top_findings": [
            {"severity": f.severity, "title": f.title[:150], "target": f.target}
            for f in findings[:10]
        ],
    }


def build_orchestration_messages(root_session, agent_run, cfg) -> list[dict]:
    import json

    from apps.core.domains.models import DomainAuthorization

    from .models import AITriage

    triage = AITriage.objects.filter(session=root_session, status="completed").first()
    domain_authorized = DomainAuthorization.objects.filter(
        domain__name=root_session.domain
    ).exists()

    payload = {
        "scan": scan_facts(root_session),
        "analyst_overview": triage.overview if triage else None,
        "tools_already_run": tools_already_run(root_session),
        "available_tools": _tool_catalog(),
        "domain_authorized_for_active_tools": domain_authorized,
        "previous_agent_subscan": _latest_agent_subscan_results(agent_run),
        "budget": {
            "iterations_remaining": max(cfg.max_agent_iterations - agent_run.iterations_used, 0),
            "subscans_remaining": max(cfg.max_subscans_per_scan - agent_run.subscans_launched, 0),
        },
    }
    instructions = (
        "You may schedule targeted follow-up scanning for this attack surface. "
        "Return JSON with `actions` (1-5 entries):\n"
        "- run_subscan: re-scan with a specific list of tool names from "
        "available_tools, when their output would materially change the "
        "assessment (e.g. a service was found that a not-yet-run tool covers). "
        "At most ONE run_subscan is executed per step. Never pick tools already "
        "in tools_already_run. Tools marked active require "
        "domain_authorized_for_active_tools to be true.\n"
        "- flag_finding: mark one finding_id as needing human attention, with a "
        "note saying why.\n"
        "- done: stop, with a short summary of what the follow-up work showed. "
        "Choose done when no additional tool would change the assessment — "
        "running more scans has real cost and is NOT the default."
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
