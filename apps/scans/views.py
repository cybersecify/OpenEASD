"""Django views for OpenEASD scan management."""

import logging
import threading

from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods

from .forms import StartScanForm
from .models import ScanSession, Vulnerability
from .tasks import run_scan

logger = logging.getLogger(__name__)


@require_http_methods(["GET", "POST"])
def scan_start(request):
    if request.method == "POST":
        form = StartScanForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data["domain"].strip()
            scan_type = form.cleaned_data["scan_type"]
            session = ScanSession.objects.create(domain=domain, scan_type=scan_type)
            threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
            logger.info(f"Scan started: session={session.id} domain={domain}")
            return redirect("scan-detail", session_id=session.id)
    else:
        form = StartScanForm()

    return render(request, "scans/start.html", {"form": form})


def scan_list(request):
    qs = ScanSession.objects.all()

    domain = request.GET.get("domain", "").strip()
    status_filter = request.GET.get("status", "").strip()

    if domain:
        qs = qs.filter(domain__icontains=domain)
    if status_filter:
        qs = qs.filter(status=status_filter)

    scans = qs[:50]

    if request.htmx:
        return render(request, "partials/scan_rows.html", {"scans": scans})

    return render(request, "scans/list.html", {
        "scans": scans,
        "domain": domain,
        "status_filter": status_filter,
    })


def scan_detail(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)

    vuln_counts = {
        sev: session.vulnerabilities.filter(severity=sev).count()
        for sev in ["critical", "high", "medium", "low"]
    }

    return render(request, "scans/detail.html", {
        "session": session,
        "vuln_counts": vuln_counts,
    })


def scan_status_fragment(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)

    vuln_counts = {
        sev: session.vulnerabilities.filter(severity=sev).count()
        for sev in ["critical", "high", "medium", "low"]
    }

    response = render(request, "partials/scan_status.html", {
        "session": session,
        "vuln_counts": vuln_counts,
    })

    if session.status != "running":
        response["HX-Trigger"] = "scanComplete"

    return response


def vulnerability_list(request):
    qs = Vulnerability.objects.select_related("session")

    severity = request.GET.get("severity", "").strip()
    session_id = request.GET.get("session_id", "").strip()
    domain = request.GET.get("domain", "").strip()

    if severity:
        qs = qs.filter(severity=severity)
    if session_id:
        qs = qs.filter(session_id=session_id)
    if domain:
        qs = qs.filter(session__domain__icontains=domain)

    vulns = qs[:100]

    if request.htmx:
        return render(request, "partials/vuln_rows.html", {"vulns": vulns})

    return render(request, "vulnerabilities/list.html", {
        "vulns": vulns,
        "severity": severity,
        "session_id": session_id,
        "domain": domain,
    })
