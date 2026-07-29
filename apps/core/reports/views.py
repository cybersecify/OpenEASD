"""Report export views — CSV and PDF."""

import base64
import csv
import functools
import logging
from io import BytesIO
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

# Cybersecify report logo, embedded as a base64 data-URI so the PDF engine
# (xhtml2pdf/pisa) needs no link_callback or static-file resolution. White
# variant for the dark (#0d1117) report cover.
_REPORT_LOGO = Path(__file__).resolve().parent / "brand" / "cybersecify-white-horizontal.png"


@functools.lru_cache(maxsize=1)
def _logo_data_uri() -> str:
    """Return the report logo as a `data:image/png;base64,...` URI, or "" if missing."""
    try:
        encoded = base64.b64encode(_REPORT_LOGO.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        logger.warning("[reports] logo asset missing at %s", _REPORT_LOGO)
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
        # Affected endpoints as a pill grid (3 per row) — xhtml2pdf renders
        # bordered table cells reliably but not inline-block spans.
        endpoints = [(f.url.url if f.url else f.target) for f in grp["instances"]]
        grp["endpoint_rows"] = [endpoints[i:i + 3] for i in range(0, len(endpoints), 3)]
    return result


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
    groups_by_severity = [
        (sev, [g for g in issue_groups if g["severity"] == sev])
        for sev in _SEVERITY_ORDER
    ]
    groups_by_severity = [(sev, gs) for sev, gs in groups_by_severity if gs]
    risk_rating = _risk_rating(vuln_counts)

    # Asset counts
    asset_counts = {
        "subdomains": Subdomain.objects.filter(session=session, is_active=True).count(),
        "ips": IPAddress.objects.filter(session=session).count(),
        "ports": Port.objects.filter(session=session).count(),
        "urls": URL.objects.filter(session=session).count(),
    }

    # Scope & methodology — the registered scan pipeline, grouped by phase group,
    # with the findings each group raised in this scan. Purely from the registry.
    from apps.core.workflows.registry import get_registry
    src_counts = {}
    for row in findings.order_by().values("source").annotate(n=Count("id")):
        src_counts[row["source"]] = row["n"]
    _pg = {}
    for name, info in get_registry().items():
        if info.get("core"):
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
    tool_count = sum(1 for _n, i in get_registry().items() if not i.get("core"))

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
        "vuln_counts": vuln_counts,
        "total_findings": sum(vuln_counts.values()),
        "risk_rating": risk_rating,
        "asset_counts": asset_counts,
        "methodology": methodology,
        "tool_count": tool_count,
        "vector_count": len(methodology),
        "scan_duration": scan_duration,
        "generated_at": timezone.now(),
        "logo_data_uri": _logo_data_uri(),
        # Optional CTA — template renders the block only when both are truthy.
        "report_cta_url": getattr(settings, "REPORT_CTA_URL", "") or "",
        "report_cta_text": getattr(settings, "REPORT_CTA_TEXT", "") or "",
    })

    from xhtml2pdf import pisa

    result = BytesIO()
    pdf = pisa.CreatePDF(html, dest=result)
    if pdf.err:
        return HttpResponse("PDF generation failed", status=500)

    response = HttpResponse(result.getvalue(), content_type="application/pdf")
    response["Content-Disposition"] = (
        f'attachment; filename="scan_report_{session.domain}_{session.id}.pdf"'
    )
    return response
