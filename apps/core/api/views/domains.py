import json
import logging

from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_http_methods

from apps.core.api.decorators import api_login_required
from apps.core.insights.builder import _rebuild_finding_type_summaries
from apps.core.api.serializers import api_response, serialize_domain
from apps.core.domains.models import Domain
from apps.core.findings.models import Finding
from apps.core.insights.models import ScanSummary
from apps.core.queries import latest_session_ids
from apps.core.scans.models import ScanSession

logger = logging.getLogger(__name__)


def _enrich_domains(domains):
    """Attach last_scan and findings_summary to each Domain object in-place."""
    domain_names = [d.name for d in domains]
    if not domain_names:
        return

    # Latest session per domain (any status) — for Last Scan column
    latest_sessions = {}
    for session in ScanSession.objects.filter(
        domain__in=domain_names
    ).order_by("domain", "-start_time"):
        if session.domain not in latest_sessions:
            latest_sessions[session.domain] = session

    # Open findings from latest completed session — for Findings column
    latest_ids = latest_session_ids(domains=domain_names)
    findings_by_domain = {}
    if latest_ids:
        for row in (
            Finding.objects
            .filter(session_id__in=latest_ids, status="open")
            .exclude(severity="info")
            .values("session__domain", "severity")
            .annotate(count=Count("id"))
        ):
            d = row["session__domain"]
            findings_by_domain.setdefault(d, {})[row["severity"]] = row["count"]

    for domain in domains:
        domain.last_scan = latest_sessions.get(domain.name)
        domain.findings_summary = findings_by_domain.get(domain.name, {})


@api_login_required
def api_domain_list(request):
    if request.method == "GET":
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        return api_response([serialize_domain(d) for d in domains])

    if request.method == "POST":
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return api_response(errors={"detail": ["Invalid JSON body."]}, status=400)

        name = body.get("name", "").strip() if isinstance(body.get("name"), str) else ""
        if not name:
            return api_response(errors={"name": ["This field is required."]}, status=400)

        if Domain.objects.filter(name=name).exists():
            return api_response(errors={"name": ["Domain already exists."]}, status=400)

        domain = Domain.objects.create(name=name)
        domain.last_scan = None
        domain.findings_summary = {}
        return api_response(serialize_domain(domain), status=201)

    return api_response(errors="Method not allowed.", status=405)


@api_login_required
def api_domain_toggle(request, pk):
    if request.method != "POST":
        return api_response(errors="Method not allowed.", status=405)

    domain = get_object_or_404(Domain, pk=pk)
    domain.is_active = not domain.is_active
    domain.save()
    _enrich_domains([domain])
    return api_response(serialize_domain(domain))


@api_login_required
def api_domain_delete(request, pk):
    if request.method != "POST":
        return api_response(errors="Method not allowed.", status=405)

    domain = get_object_or_404(Domain, pk=pk)
    domain_name = domain.name

    active = ScanSession.objects.filter(
        domain=domain_name, status__in=["pending", "running"]
    ).exists()
    if active:
        return api_response(
            errors="Cannot delete — a scan is currently active.",
            status=409,
        )

    with transaction.atomic():
        ScanSession.objects.filter(domain=domain_name).delete()
        ScanSummary.objects.filter(domain=domain_name).delete()
        domain.delete()

    _rebuild_finding_type_summaries()

    return api_response({"deleted": domain_name})
