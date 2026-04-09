"""Django views for OpenEASD scan management."""

import logging
import threading

from django.db.models import Q
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods

from .forms import StartScanForm
from .models import ScanSession
from .tasks import run_scan

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ["critical", "high", "medium", "low"]


def _get_vuln_counts(session):
    """Aggregate finding counts by severity across all tool apps."""
    counts = {sev: 0 for sev in SEVERITY_LEVELS}
    try:
        for sev in SEVERITY_LEVELS:
            counts[sev] += session.nuclei_findings.filter(severity=sev).count()
            counts[sev] += session.dns_findings.filter(severity=sev).count()
            counts[sev] += session.ssl_findings.filter(severity=sev).count()
            counts[sev] += session.email_findings.filter(severity=sev).count()
    except Exception:
        pass
    return counts


@require_http_methods(["GET", "POST"])
def scan_start(request):
    if request.method == "POST":
        form = StartScanForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data["domain"].strip()
            scan_type = form.cleaned_data["scan_type"]
            workflow_id = form.cleaned_data.get("workflow") or None
            session = ScanSession.objects.create(domain=domain, scan_type=scan_type, workflow_id=workflow_id)
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
    vuln_counts = _get_vuln_counts(session)

    return render(request, "scans/detail.html", {
        "session": session,
        "vuln_counts": vuln_counts,
    })


def scan_status_fragment(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)
    vuln_counts = _get_vuln_counts(session)

    response = render(request, "partials/scan_status.html", {
        "session": session,
        "vuln_counts": vuln_counts,
    })

    if session.status != "running":
        response["HX-Trigger"] = "scanComplete"

    return response


def vulnerability_list(request):
    """Aggregate view across all finding types (severity >= medium by default)."""
    from apps.nuclei.models import NucleiFinding
    from apps.dns_analyzer.models import DNSFinding
    from apps.ssl_checker.models import SSLFinding
    from apps.email_security.models import EmailFinding

    severity = request.GET.get("severity", "").strip()
    session_id = request.GET.get("session_id", "").strip()
    domain = request.GET.get("domain", "").strip()

    def _filter(qs, sev_field="severity"):
        if severity:
            qs = qs.filter(**{sev_field: severity})
        if session_id:
            qs = qs.filter(session_id=session_id)
        if domain:
            qs = qs.filter(session__domain__icontains=domain)
        return qs

    nuclei = list(_filter(NucleiFinding.objects.select_related("session"))[:50])
    dns = list(_filter(DNSFinding.objects.select_related("session"))[:50])
    ssl = list(_filter(SSLFinding.objects.select_related("session"))[:50])
    email = list(_filter(EmailFinding.objects.select_related("session"))[:50])

    # Combine into unified list with a source tag
    vulns = []
    for f in nuclei:
        vulns.append({"source": "nuclei", "severity": f.severity, "title": f.template_name or f.template_id,
                      "host": f.host, "session": f.session, "obj": f})
    for f in dns:
        vulns.append({"source": "dns", "severity": f.severity, "title": f.title,
                      "host": f.domain, "session": f.session, "obj": f})
    for f in ssl:
        vulns.append({"source": "ssl", "severity": f.severity, "title": f.title,
                      "host": f.domain, "session": f.session, "obj": f})
    for f in email:
        vulns.append({"source": "email", "severity": f.severity, "title": f.title,
                      "host": f.domain, "session": f.session, "obj": f})

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    vulns.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

    if request.htmx:
        return render(request, "partials/vuln_rows.html", {"vulns": vulns})

    return render(request, "vulnerabilities/list.html", {
        "vulns": vulns,
        "severity": severity,
        "session_id": session_id,
        "domain": domain,
    })
