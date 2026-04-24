"""Report export views — CSV and PDF."""

import csv
import functools
from io import BytesIO

from django.contrib.auth.models import User
from django.db.models import Count
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.template.loader import get_template
from django.utils import timezone

from apps.core.constants import SEVERITY_LEVELS
from apps.core.assets.models import Subdomain, IPAddress, Port
from apps.core.web_assets.models import URL
from apps.core.findings.models import Finding
from apps.core.scans.models import ScanSession


def _report_auth_required(view_func):
    """Accept Django session auth OR JWT access token via ?token= query param."""
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
            except Exception:
                pass
        return HttpResponseRedirect('/login')
    return wrapper


@_report_auth_required
def export_findings_csv(request, session_uuid):
    """Export all findings for a scan session as CSV."""
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    findings = Finding.objects.filter(session=session).order_by("severity", "source")

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
    return response


@_report_auth_required
def export_scan_pdf(request, session_uuid):
    """Export a scan report as PDF."""
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    findings = Finding.objects.filter(session=session).order_by("severity", "-discovered_at")

    # Severity counts
    vuln_counts = {sev: 0 for sev in SEVERITY_LEVELS}
    for row in findings.values("severity").annotate(total=Count("id")):
        if row["severity"] in vuln_counts:
            vuln_counts[row["severity"]] = row["total"]

    # Asset counts
    asset_counts = {
        "subdomains": Subdomain.objects.filter(session=session, is_active=True).count(),
        "ips": IPAddress.objects.filter(session=session).count(),
        "ports": Port.objects.filter(session=session).count(),
        "urls": URL.objects.filter(session=session).count(),
    }

    template = get_template("reports/scan_report.html")
    html = template.render({
        "session": session,
        "findings": findings,
        "vuln_counts": vuln_counts,
        "asset_counts": asset_counts,
        "generated_at": timezone.now(),
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
