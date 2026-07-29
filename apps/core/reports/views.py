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
        key = (f.severity, f.source, f.check_type, f.description, f.remediation)
        g = groups.get(key)
        if g is None:
            title = f.title or ""
            suffix = " on " + (f.target or "")
            if f.target and title.endswith(suffix):
                title = title[: -len(suffix)]
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

    # Asset counts
    asset_counts = {
        "subdomains": Subdomain.objects.filter(session=session, is_active=True).count(),
        "ips": IPAddress.objects.filter(session=session).count(),
        "ports": Port.objects.filter(session=session).count(),
        "urls": URL.objects.filter(session=session).count(),
    }

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
        "unique_issue_count": len(issue_groups),
        "vuln_counts": vuln_counts,
        "total_findings": sum(vuln_counts.values()),
        "asset_counts": asset_counts,
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
