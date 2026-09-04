"""Report export views — CSV and PDF."""

import base64
import csv
import functools
import logging
from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import Count
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.template.loader import get_template
from django.utils import timezone

from apps.core.assets.models import Subdomain, IPAddress, Port
from apps.core.web_assets.models import URL
from apps.core.findings.models import Finding
from apps.core.scans.models import ScanSession

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_ALLOWED_SEVERITIES = frozenset(_SEVERITY_ORDER)

# Representative CVSS v3.1 base score per severity band, used when a finding has
# no measured CVSS (only CVE findings carry a real score in extra["cvss_score"]).
_SEVERITY_CVSS = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1}

# scope: coarse category shown next to each finding. check_type wins over source.
_SCOPE_BY_SOURCE = {
    "tls_checker": "TLS / HTTPS",
    "ssh_checker": "Network / SSH",
    "nmap": "Network",
    "nuclei_network": "Network",
    "domain_security": "Email / DNS",
    "web_checker": "Web",
    "nuclei": "Web",
    "httpx": "Web",
    "takeover_check": "Attack Surface",
    "cloud_assets": "Cloud Storage",
}
_SCOPE_BY_CHECK = {
    "rdap": "Domain", "dns": "DNS", "caa": "DNS", "dnssec": "DNS",
    "open_relay": "Email / DNS",
}

# CWE mapping per check_type. Unmapped check types render "—".
_CWE_BY_CHECK = {
    "unencrypted_service": "CWE-319: Cleartext Transmission of Sensitive Information",
    "missing_hsts": "CWE-319: Cleartext Transmission of Sensitive Information",
    "san_mismatch": "CWE-295: Improper Certificate Validation",
    "self_signed_cert": "CWE-295: Improper Certificate Validation",
    "untrusted_ca": "CWE-295: Improper Certificate Validation",
    "cert_expiring": "CWE-324: Use of a Key Past its Expiration Date",
    "missing_csp": "CWE-1021: Improper Restriction of Rendered UI Layers",
    "missing_xfo": "CWE-1021: Improper Restriction of Rendered UI Layers",
    "missing_xcto": "CWE-693: Protection Mechanism Failure",
    "cors": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
    "cve": "CWE-1395: Dependency on Vulnerable Third-Party Component",
    "weak_ssh_kex": "CWE-326: Inadequate Encryption Strength",
    "weak_ssh_mac": "CWE-326: Inadequate Encryption Strength",
    "weak_cipher": "CWE-326: Inadequate Encryption Strength",
    "email": "CWE-358: Improperly Implemented Security Check for Standard",
    "dmarc": "CWE-358: Improperly Implemented Security Check for Standard",
    "spf": "CWE-358: Improperly Implemented Security Check for Standard",
    "dkim": "CWE-358: Improperly Implemented Security Check for Standard",
    "dnssec": "CWE-346: Origin Validation Error",
    "dns": "CWE-693: Protection Mechanism Failure",
    "open_relay": "CWE-284: Improper Access Control",
    "rdap": "CWE-284: Improper Access Control",
    "sshv1_supported": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "weak_ssh_host_key": "CWE-326: Inadequate Encryption Strength",
    "weak_ssh_cipher": "CWE-326: Inadequate Encryption Strength",
    "ssh_password_auth": "CWE-287: Improper Authentication",
    "ssh_root_login": "CWE-269: Improper Privilege Management",
    # TLS checker
    "cert_expired": "CWE-324: Use of a Key Past its Expiration Date",
    "cert_expiring_critical": "CWE-324: Use of a Key Past its Expiration Date",
    "cert_expiring_soon": "CWE-324: Use of a Key Past its Expiration Date",
    "no_forward_secrecy": "CWE-326: Inadequate Encryption Strength",
    "tls10_supported": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "tls11_supported": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "tls13_not_supported": "CWE-326: Inadequate Encryption Strength",
    "weak_rsa_key": "CWE-326: Inadequate Encryption Strength",
    "weak_ec_key": "CWE-326: Inadequate Encryption Strength",
    "dsa_key": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "sha1_cert_signature": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "no_sct": "CWE-295: Improper Certificate Validation",
    # Web checker
    "missing_permissions_policy": "CWE-693: Protection Mechanism Failure",
    "missing_referrer_policy": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
    "weak_hsts": "CWE-319: Cleartext Transmission of Sensitive Information",
    "cookie_missing_secure": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "cookie_missing_httponly": "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
    "cookie_missing_samesite": "CWE-1275: Sensitive Cookie with Improper SameSite Attribute",
    "cors_wildcard_credentials": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
    "cors_origin_reflection": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
    "cors_wildcard": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
    "server_version_disclosure": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
    "server_poweredby_disclosure": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
    "directory_listing": "CWE-548: Exposure of Information Through Directory Listing",
    # Attack surface / cloud / secrets / intel
    "subdomain_takeover": "CWE-284: Improper Access Control",
    "open_cloud_bucket": "CWE-732: Incorrect Permission Assignment for Critical Resource",
    "exposed_secret": "CWE-540: Inclusion of Sensitive Information in Source Code",
    "infostealer_exposure": "CWE-522: Insufficiently Protected Credentials",
    "asn": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
    "coverage_regression": "CWE-693: Protection Mechanism Failure",
    "shodan_exposure": "CWE-668: Exposure of Resource to Wrong Sphere",
}


def _finding_scope(source, check_type):
    return _SCOPE_BY_CHECK.get(check_type) or _SCOPE_BY_SOURCE.get(source) or "General"


def _risk_rating(vuln_counts):
    """Overall posture rating computed from severity counts (no analysis)."""
    if vuln_counts.get("critical"):
        return "CRITICAL"
    if vuln_counts.get("high"):
        return "HIGH"
    if vuln_counts.get("medium"):
        return "MEDIUM"
    if vuln_counts.get("low"):
        return "LOW"
    return "INFORMATIONAL"


# Human labels for fingerprinted WAF/edge vendors.
_WAF_VENDOR_LABEL = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "sucuri": "Sucuri",
    "imperva": "Imperva",
    "aws": "AWS",
    "f5": "F5",
    "barracuda": "Barracuda",
    "ddos-guard": "DDoS-Guard",
}


def _collect_technologies(session):
    """Distinct technologies fingerprinted across a session's web assets.

    Aggregates the per-URL ``technologies`` lists (httpx -tech-detect),
    de-duplicates case-insensitively (first spelling wins), and returns them
    sorted case-insensitively. Informational only — no version/EOL/CVE
    inference. Returns [] when nothing was fingerprinted.
    """
    seen = {}
    for row in URL.objects.filter(session=session).values_list("technologies", flat=True):
        for tech in (row or []):
            if not isinstance(tech, str):
                continue
            tech = tech.strip()
            if tech:
                seen.setdefault(tech.lower(), tech)
    return sorted(seen.values(), key=str.lower)


def _coverage_context(session):
    """Scan Coverage block for the report (spec C2).

    Returns None when no edge interference was observed (no block/challenge on any
    probed endpoint), so the report renders the block only when it applies.
    Reports the *observation* + a hedged vendor guess — never the WAF config, and
    an endpoint count, never a request percentage (that is a Phase 2 output).
    """
    blocked = session.endpoints_blocked
    if not blocked:
        return None
    vendor = session.waf_vendor
    probed = session.endpoints_probed
    if vendor and vendor != "unidentified":
        vendor_phrase = f"fingerprint suggests {_WAF_VENDOR_LABEL.get(vendor, vendor.title())}"
    else:
        vendor_phrase = "WAF/edge, vendor unidentified"

    # Two distinct shapes both land in `endpoints_blocked`:
    #  - vendor set  -> endpoints RESPONDED with a block/challenge page (real WAF)
    #  - vendor ""   -> endpoints returned NOTHING (silent drop). Do not claim they
    #    "returned block/challenge responses" — they didn't respond at all, and the
    #    count can also include probed ports that simply aren't HTTP services.
    if vendor:
        observation = (
            f"{blocked} of {probed} probed endpoints returned block or challenge "
            f"responses ({vendor_phrase})"
        )
    else:
        observation = (
            f"{blocked} of {probed} probed endpoints did not return an HTTP response "
            f"— probes appear to have been dropped/blocked at the network edge (or "
            f"the port is not an HTTP service)"
        )
    return {
        "endpoints_probed": probed,
        "endpoints_blocked": blocked,
        "vendor_phrase": vendor_phrase,
        "note": (
            f"{observation}. Findings reflect only reachable endpoints. Absence of "
            f"findings on unreachable surfaces is not evidence they are secure. To "
            f"obtain full-coverage results, allowlist the scanner (OpenEASD/1.0, "
            f"source IP on file) at your edge/WAF and re-run."
        ),
    }

# Cybersecify report logos, embedded as base64 data-URIs. "white" is used on the
# dark (#0d1117) cover; "brand" (green) is used in the running header on white
# body pages, where the white logo would be invisible.
_BRAND_DIR = Path(__file__).resolve().parent / "brand"


@functools.lru_cache(maxsize=4)
def _logo_data_uri(variant: str = "white") -> str:
    """Return a report logo as a `data:image/png;base64,...` URI, or "" if missing."""
    path = _BRAND_DIR / f"cybersecify-{variant}-horizontal.png"
    try:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        logger.warning("[reports] logo asset missing at %s", path)
        return ""


def _parse_min_severity(request):
    """Return (severities_list, None) or (None, 400 response) for ?min_severity= param."""
    min_sev = request.GET.get("min_severity", "info").lower()
    if min_sev not in _ALLOWED_SEVERITIES:
        return None, HttpResponse(
            f"Invalid min_severity. Allowed: {', '.join(_SEVERITY_ORDER)}",
            status=400,
            content_type="text/plain",
        )
    return _SEVERITY_ORDER[: _SEVERITY_ORDER.index(min_sev) + 1], None


def _report_auth_required(view_func):
    """Accept auth in this order:

    1. Django session (request.user already authenticated)
    2. ``Authorization: Bearer <token>`` header — preferred; React SPA uses
       this via fetch + Blob for downloads
    3. ``?token=<token>`` query param — DEPRECATED, retained for backward
       compatibility only and slated for removal in a future release

    The ``?token=`` path leaks JWTs into browser history, ``Referer`` headers,
    server access logs, and proxy caches. The frontend no longer generates
    such URLs; only manually constructed links exercise this path.
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            return view_func(request, *args, **kwargs)

        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = request.GET.get('token', '')

        if token:
            try:
                from ninja_jwt.tokens import AccessToken
                token_obj = AccessToken(token)
                user_id = token_obj["user_id"]
                request.user = User.objects.get(id=user_id, is_active=True)
                return view_func(request, *args, **kwargs)
            except Exception as exc:
                logger.debug(f"Report token auth failed: {exc}")
        return HttpResponseRedirect('/login')
    return wrapper


@_report_auth_required
def export_findings_csv(request, session_uuid):
    """Export findings for a scan session as CSV, optionally filtered by ?min_severity=."""
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    severities, err = _parse_min_severity(request)
    if err:
        return err
    findings = Finding.objects.filter(session=session, severity__in=severities).order_by("severity", "source")

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        f'attachment; filename="findings_{session.domain}_{session.id}.csv"'
    )

    writer = csv.writer(response)
    writer.writerow([
        "Title", "Severity", "Source", "Check Type", "Status",
        "Target", "Description", "Remediation", "Assigned To", "Discovered At",
    ])
    for f in findings:
        writer.writerow([
            f.title, f.severity, f.source, f.check_type, f.status,
            f.target, f.description, f.remediation, f.assigned_to,
            f.discovered_at.isoformat(),
        ])

    # Optional CTA — appended as a final row when both settings are configured.
    # Self-hosters with no CTA configured get a clean CSV.
    cta_url = getattr(settings, "REPORT_CTA_URL", "") or ""
    cta_text = getattr(settings, "REPORT_CTA_TEXT", "") or ""
    if cta_url and cta_text:
        writer.writerow([])  # spacer row
        writer.writerow([cta_text, "", "", "", "", cta_url])

    return response


def _group_findings_by_issue(findings):
    """Collapse findings that share an identical write-up into one issue group.

    Many tools raise the same issue (identical severity/source/check_type/
    description/remediation) once per affected target — e.g. 20 "Unencrypted
    HTTPS" findings differing only by IP:port. Grouping renders the description
    and remediation once, with a compact table of every affected target beneath,
    instead of repeating the full block per instance. No information is lost:
    every target is still listed.

    Returns a list of dicts ordered by severity, then by instance count (desc):
        {severity, source, check_type, title, description, remediation, instances}
    where `instances` is the list of Finding objects sharing that write-up.
    The group title strips a trailing " on <target>" so the heading reads as the
    issue ("Unencrypted HTTPS") rather than one instance's target.
    """
    groups = {}
    order = []
    for f in findings:
        # Normalise the title by stripping a trailing " on <target>" so the same
        # issue across targets shares one heading ("Unencrypted HTTPS").
        title = f.title or ""
        suffix = " on " + (f.target or "")
        if f.target and title.endswith(suffix):
            title = title[: -len(suffix)]
        # Group on the issue identity (severity + source + check_type + heading),
        # NOT on the full description — real findings embed per-target text in the
        # description, which would otherwise split one issue into many groups.
        key = (f.severity, f.source, f.check_type, title)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "severity": f.severity,
                "source": f.source,
                "check_type": f.check_type,
                "title": title,
                "description": f.description,
                "remediation": f.remediation,
                "instances": [],
            }
            order.append(key)
        g["instances"].append(f)

    result = [groups[k] for k in order]
    result.sort(
        key=lambda grp: (
            _SEVERITY_ORDER.index(grp["severity"]) if grp["severity"] in _SEVERITY_ORDER else 99,
            -len(grp["instances"]),
            grp["title"].lower(),
        )
    )

    # Enrich each group: stable ID, scope, CWE, CVSS, and de-duplicated CVE list.
    year = timezone.now().year
    for i, grp in enumerate(result, start=1):
        grp["fid"] = f"OE-{year}-{i:03d}"
        grp["scope"] = _finding_scope(grp["source"], grp["check_type"])
        grp["cwe"] = _CWE_BY_CHECK.get(grp["check_type"], "")
        # Real CVSS from CVE findings if present, else the severity-band default.
        scores = [
            f.extra.get("cvss_score")
            for f in grp["instances"]
            if isinstance(f.extra, dict) and f.extra.get("cvss_score")
        ]
        grp["cvss"] = max(scores) if scores else _SEVERITY_CVSS.get(grp["severity"])
        cves = []
        for f in grp["instances"]:
            if not isinstance(f.extra, dict):
                continue
            one = f.extra.get("cve")
            many = f.extra.get("cve_ids") or []
            for c in ([one] if one else []) + list(many):
                if c and c not in cves:
                    cves.append(c)
        grp["cves"] = cves
        # Threat intel rollup from cve_intel (extra: cisa_kev / epss_score /
        # epss_percentile). KEV = at least one CVE is on CISA's actively-exploited
        # list; EPSS percentile is the highest across the group's CVEs.
        dict_extras = [f.extra for f in grp["instances"] if isinstance(f.extra, dict)]
        grp["cisa_kev"] = any(e.get("cisa_kev") for e in dict_extras)
        pctls = [e.get("epss_percentile") for e in dict_extras if e.get("epss_percentile") is not None]
        grp["epss_percentile"] = max(pctls) if pctls else None
        # Plain-language business impact, shown on critical/high finding cards so
        # a decision-maker (not just an engineer) understands what's at stake.
        grp["business_impact"] = (
            _BUSINESS_IMPACT.get(grp["check_type"]) or _BUSINESS_IMPACT_BY_SEV.get(grp["severity"], "")
        ) if grp["severity"] in ("critical", "high") else ""
        # Affected endpoints as a pill grid (3 per row). Capped at 50 per group
        # to prevent OOM when a single finding fires on thousands of URLs.
        endpoints = [(f.url.url if f.url else f.target) for f in grp["instances"]]
        cap = 50
        shown = endpoints[:cap]
        grp["endpoint_rows"] = [shown[i:i + 3] for i in range(0, len(shown), 3)]
        grp["endpoint_overflow"] = max(0, len(endpoints) - cap)
    return result


# Plain-language business risk for the headline "Fix First" block — spoken to a
# decision-maker, not an engineer. Keyed by check_type; severity fallback below.
_BUSINESS_IMPACT = {
    "unencrypted_service": "Data to this service crosses the internet in plaintext — anyone on the network path can read it.",
    "subdomain_takeover": "An attacker can claim this dangling subdomain and serve content under your name — phishing, malware, or session-cookie theft.",
    "missing_csp": "A single injected script would run in your users' browsers (cross-site scripting).",
    "cve": "A publicly known vulnerability with a documented exploit is reachable from the internet.",
    "dnssec": "DNS answers for your domain can be forged, silently redirecting users to attacker servers.",
    "dmarc": "Anyone can send email that appears to come from your domain — brand and phishing risk.",
    "mta_sts": "Email to your mail servers can be forced down to plaintext and intercepted in transit.",
    "rdap": "Your domain registration lapses soon — expiry means outage and a hijack window.",
}
_BUSINESS_IMPACT_BY_SEV = {
    "critical": "Directly exploitable from the internet and high-impact — treat as urgent.",
    "high": "A serious weakness an external attacker can leverage.",
}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _priority_score(grp) -> float:
    """Rank findings for the 'Fix First' block: severity first, then measured
    CVSS, with a dominant boost for actively-exploited (CISA KEV) issues and a
    nudge for high EPSS (exploit-probability)."""
    score = _SEV_RANK.get(grp["severity"], 0) * 100
    score += (grp.get("cvss") or 0) * 5
    if grp.get("cisa_kev"):
        score += 500  # actively exploited in the wild dominates the ranking
    if grp.get("epss_percentile"):
        score += grp["epss_percentile"] * 50
    return score


def _top_risks(groups, limit=5):
    """The decision-maker's shortlist: critical/high (or actively-exploited)
    issues, ranked by priority, each with a plain-language impact line."""
    candidates = [
        g for g in groups
        if g["severity"] in ("critical", "high") or g.get("cisa_kev")
    ]
    ranked = sorted(candidates, key=_priority_score, reverse=True)[:limit]
    for g in ranked:
        # Reuse the per-group business_impact; fall back for KEV-only mediums.
        g["impact"] = g.get("business_impact") or \
            _BUSINESS_IMPACT.get(g["check_type"]) or \
            _BUSINESS_IMPACT_BY_SEV.get(g["severity"], "")
    return ranked


def _render_pdf(html: str) -> bytes:
    """Render report HTML to PDF bytes via WeasyPrint.

    WeasyPrint needs the pango / cairo / gdk-pixbuf system libraries. This is
    isolated in one function so tests can patch it without importing WeasyPrint
    or requiring those libraries.
    """
    from weasyprint import HTML

    return HTML(string=html).write_pdf()


@_report_auth_required
def export_scan_pdf(request, session_uuid):
    """Export a scan report as PDF, optionally filtered by ?min_severity=."""
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    severities, err = _parse_min_severity(request)
    if err:
        return err
    findings = Finding.objects.filter(session=session, severity__in=severities).select_related("port", "url").order_by(
        "severity", "-discovered_at"
    )

    # Severity counts. Reset the queryset ordering with .order_by() first: the
    # `findings` queryset is ordered by (severity, -discovered_at), and that
    # trailing sort field would otherwise leak into the GROUP BY, collapsing
    # every severity bucket to a count of 1 (one group per distinct timestamp).
    vuln_counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for row in findings.order_by().values("severity").annotate(total=Count("id")):
        if row["severity"] in vuln_counts:
            vuln_counts[row["severity"]] = row["total"]

    # Findings collapsed into issue groups (identical write-up → one block with
    # a table of affected targets) for both the overview and the detail section.
    issue_groups = _group_findings_by_issue(findings)
    top_risks = _top_risks(issue_groups)
    groups_by_severity = [
        (sev, [g for g in issue_groups if g["severity"] == sev])
        for sev in _SEVERITY_ORDER
    ]
    groups_by_severity = [(sev, gs) for sev, gs in groups_by_severity if gs]
    # Consolidated (unique-issue) severity counts drive the headline tiles and the
    # risk rating, so they match the findings table. The raw per-detection counts
    # (vuln_counts) are surfaced only as the "N raw detections" note.
    unique_counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for g in issue_groups:
        if g["severity"] in unique_counts:
            unique_counts[g["severity"]] += 1
    raw_total = sum(vuln_counts.values())
    risk_rating = _risk_rating(unique_counts)

    # Asset counts
    asset_counts = {
        "subdomains": Subdomain.objects.filter(session=session, is_active=True).count(),
        "ips": IPAddress.objects.filter(session=session).count(),
        "ports": Port.objects.filter(session=session).count(),
        "urls": URL.objects.filter(session=session).count(),
    }

    # Technology stack — the distinct technologies fingerprinted across all web
    # assets (httpx -tech-detect). Informational only: no version/EOL/CVE
    # inference. Sorted case-insensitively, deduped.
    technologies = _collect_technologies(session)

    # Scope & methodology — tools that ran in this scan's workflow, grouped by
    # phase group, with findings each group raised.
    from apps.core.workflows.registry import get_registry
    registry = get_registry()
    # Workflow's chosen tools + always-on core tools (e.g. service_detection)
    workflow_tools = (
        set(session.workflow.enabled_tools()) if session.workflow_id
        else {n for n, i in registry.items() if not i.get("core")}
    )
    core_tools = {n for n, i in registry.items() if i.get("core")}
    active_tools = workflow_tools | core_tools
    src_counts = {}
    for row in findings.order_by().values("source").annotate(n=Count("id")):
        src_counts[row["source"]] = row["n"]
    _pg = {}
    for name, info in registry.items():
        if name not in active_tools:
            continue
        group = info.get("phase_group") or "Other"
        d = _pg.setdefault(group, {"phase": info["phase"], "tools": [], "findings": 0, "produces": False})
        d["phase"] = min(d["phase"], info["phase"])
        d["tools"].append(info["label"])
        d["findings"] += src_counts.get(name, 0)
        d["produces"] = d["produces"] or info.get("produces_findings", False)
    methodology = sorted(
        ({"vector": g, "tools": v["tools"], "findings": v["findings"],
          "produces": v["produces"], "phase": v["phase"]} for g, v in _pg.items()),
        key=lambda r: r["phase"],
    )
    tool_count = len(active_tools)

    # Workflow step diagnostics — only populated for partial scans
    workflow_steps = []
    if session.status == "partial":
        from apps.core.workflows.models import WorkflowRun, WorkflowStepResult
        run = WorkflowRun.objects.filter(session=session).first()
        if run:
            for step in WorkflowStepResult.objects.filter(run=run).order_by("order"):
                dur = None
                if step.started_at and step.finished_at:
                    dur = int((step.finished_at - step.started_at).total_seconds())
                workflow_steps.append({
                    "tool": step.tool,
                    "status": step.status,
                    "duration": dur,
                    "error": step.error or "",
                })

    # Scan duration
    scan_duration = None
    if session.end_time and session.start_time:
        delta = session.end_time - session.start_time
        total_seconds = int(delta.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            scan_duration = f"{hours}h {minutes}m {seconds}s"
        elif minutes:
            scan_duration = f"{minutes}m {seconds}s"
        else:
            scan_duration = f"{seconds}s"

    template = get_template("reports/scan_report.html")
    html = template.render({
        "session": session,
        "issue_groups": issue_groups,
        "groups_by_severity": groups_by_severity,
        "unique_issue_count": len(issue_groups),
        "vuln_counts": unique_counts,          # tiles/risk reflect consolidated issues
        "total_findings": len(issue_groups),   # headline = unique issue count
        "raw_total": raw_total,                # raw detections, shown only in the note
        "risk_rating": risk_rating,
        "top_risks": top_risks,
        "headline_risk": top_risks[0] if top_risks else None,
        "coverage": _coverage_context(session),
        "asset_counts": asset_counts,
        "technologies": technologies,
        "methodology": methodology,
        "tool_count": tool_count,
        "vector_count": len(methodology),
        "scan_duration": scan_duration,
        "workflow_steps": workflow_steps,
        "generated_at": timezone.now(),
        "logo_data_uri": _logo_data_uri("white"),          # dark cover
        "header_logo_data_uri": _logo_data_uri("brand"),   # light-page running header
        # Optional CTA — template renders the block only when both are truthy.
        "report_cta_url": getattr(settings, "REPORT_CTA_URL", "") or "",
        "report_cta_text": getattr(settings, "REPORT_CTA_TEXT", "") or "",
    })

    try:
        pdf_bytes = _render_pdf(html)
    except Exception:
        logger.exception("[reports] PDF generation failed")
        return HttpResponse("PDF generation failed", status=500)

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = (
        f'attachment; filename="scan_report_{session.domain}_{session.id}.pdf"'
    )
    return response
