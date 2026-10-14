"""Report export views — CSV."""

import csv
import functools
import logging

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404

from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_ALLOWED_SEVERITIES = frozenset(_SEVERITY_ORDER)










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
    """Require a Django session (the server-rendered mvp UI is session-authed).

    A user still on the forced-change flag (e.g. default admin/admin) must not
    reach report data — reports is a direct view, so enforce that explicitly
    here rather than relying only on the mvp middleware.
    """
    def _password_change_pending(user) -> bool:
        profile = getattr(user, "profile", None)
        return bool(profile is not None and profile.must_change_password)

    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            if _password_change_pending(request.user):
                return HttpResponseRedirect('/change-password')
            return view_func(request, *args, **kwargs)
        return HttpResponseRedirect('/login')
    return wrapper


@_report_auth_required
def export_findings_csv(request, session_uuid):
    """Export findings for a scan session as CSV, optionally filtered by ?min_severity=."""
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    severities, err = _parse_min_severity(request)
    if err:
        return err
    findings = (
        Finding.objects.filter(session=session, severity__in=severities)
        .exclude(title__in=_REPORT_HIDDEN_TITLES)
        .order_by("severity", "source")
    )

    # Keys (source:check_type:title) that weren't present in the previous scan,
    # so each row can be flagged "new" — the CSV counterpart of the PDF's
    # "Since Your Last Scan" block.
    new_keys = set()
    previous = _previous_baseline(session)
    if previous is not None:
        prev_keys = {
            f"{r['source']}:{r['check_type']}:{r['title']}"
            for r in Finding.objects.filter(session=previous, severity__in=severities)
            .exclude(title__in=_REPORT_HIDDEN_TITLES)
            .values("source", "check_type", "title")
        }
        cur_keys = {
            f"{r['source']}:{r['check_type']}:{r['title']}"
            for r in findings.values("source", "check_type", "title")
        }
        new_keys = cur_keys - prev_keys

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        f'attachment; filename="findings_{session.domain}_{session.id}.csv"'
    )

    writer = csv.writer(response)
    writer.writerow([
        "Title", "Severity", "Source", "Check Type", "Status",
        "Target", "Description", "Remediation", "Assigned To", "Discovered At",
        "New This Scan",
    ])
    for f in findings:
        key = f"{f.source}:{f.check_type}:{f.title}"
        writer.writerow([
            f.title, f.severity, f.source, f.check_type, f.status,
            f.target, f.description, f.remediation, f.assigned_to,
            f.discovered_at.isoformat(),
            "new" if key in new_keys else "",
        ])

    # Optional CTA — appended as a final row when both settings are configured.
    # Self-hosters with no CTA configured get a clean CSV.
    cta_url = getattr(settings, "REPORT_CTA_URL", "") or ""
    cta_text = getattr(settings, "REPORT_CTA_TEXT", "") or ""
    if cta_url and cta_text:
        writer.writerow([])  # spacer row
        writer.writerow([cta_text, "", "", "", "", cta_url])

    return response
















# Findings hidden from the buyer-facing report (PDF + CSV) — still stored and
# shown in the app, just noise in a report: BIMI (marketing, not security),
# the update-lock (lowest-value registrar lock), and the RDAP-lookup-failed
# notice (surfaced instead as a coverage caveat).
_REPORT_HIDDEN_TITLES = frozenset({
    "BIMI not configured",
    "Domain update lock not enabled",
    "RDAP lookup failed",
})







def _previous_baseline(session):
    """The scan to diff this one against: the most recent completed/partial scan
    of the same domain that isn't a subscan (a subscan runs only a subset of
    tools, so it would manufacture spurious deltas). Matches ScanDelta's choice.
    Returns ``None`` when this is the domain's first scan.
    """
    return (
        ScanSession.objects.filter(
            domain=session.domain, status__in=["completed", "partial"]
        )
        .exclude(id=session.id)
        .exclude(scan_type="subscan")
        .order_by("-start_time")
        .first()
    )








