"""Report export views — CSV and PDF."""

import csv
import functools
import logging
from io import BytesIO

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
    """Accept Django session auth OR JWT access token via ?token= query param.

    The ?token= mechanism is intentional for direct PDF/CSV download links where
    the browser cannot set an Authorization header. Tokens appear in server access
    logs — acceptable for a single-user local deployment.
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            return view_func(request, *args, **kwargs)
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

    # Severity counts
    SEV_ORDER = ["critical", "high", "medium", "low", "info"]
    vuln_counts = {sev: 0 for sev in SEV_ORDER}
    for row in findings.values("severity").annotate(total=Count("id")):
        if row["severity"] in vuln_counts:
            vuln_counts[row["severity"]] = row["total"]

    # Findings grouped by severity (for detail section)
    from collections import defaultdict
    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)
    grouped_findings = [(sev, by_sev[sev]) for sev in SEV_ORDER if by_sev[sev]]

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
        "findings": findings,
        "grouped_findings": grouped_findings,
        "vuln_counts": vuln_counts,
        "total_findings": sum(vuln_counts.values()),
        "asset_counts": asset_counts,
        "scan_duration": scan_duration,
        "generated_at": timezone.now(),
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
