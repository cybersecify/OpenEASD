"""Pure Django REST API views for scan management."""

import datetime
import json
import logging

from django.core.paginator import Paginator
from django.db import models
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone

from apps.core.api.decorators import api_login_required
from apps.core.api.serializers import (
    api_response,
    serialize_finding,
    serialize_ip,
    serialize_port,
    serialize_scan_session,
    serialize_scan_session_brief,
    serialize_subdomain,
    serialize_url,
    serialize_workflow_step_result,
)
from apps.core.constants import SEVERITY_LEVELS
from apps.core.insights.builder import _rebuild_finding_type_summaries
from apps.core.queries import latest_session_ids
from apps.core.scans.models import ScanSession
from apps.core.scans.views import _parse_job, _schedule_once, _schedule_recurring

logger = logging.getLogger(__name__)


def _get_vuln_counts(session):
    """Aggregate finding counts by severity — single query."""
    from apps.core.findings.models import Finding

    counts = {sev: 0 for sev in SEVERITY_LEVELS}
    for row in (
        Finding.objects.filter(session=session)
        .values("severity")
        .annotate(total=Count("id"))
    ):
        if row["severity"] in counts:
            counts[row["severity"]] = row["total"]
    return counts


@api_login_required
def api_scan_list(request):
    qs = ScanSession.objects.all().order_by("-start_time")

    domain = request.GET.get("domain", "").strip()
    status_filter = request.GET.get("status", "").strip()

    if domain:
        qs = qs.filter(domain__icontains=domain)
    if status_filter:
        qs = qs.filter(status=status_filter)

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    return api_response(
        data=[serialize_scan_session_brief(s) for s in page],
        pagination={
            "page": page.number,
            "total_pages": paginator.num_pages,
            "count": paginator.count,
            "has_next": page.has_next(),
            "has_previous": page.has_previous(),
        },
    )


@api_login_required
def api_scan_start(request):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return api_response(errors={"detail": ["Invalid JSON body."]}, status=400)

    domain = (body.get("domain") or "").strip()
    if not domain:
        return api_response(errors={"domain": ["This field is required."]}, status=400)

    schedule_type = body.get("schedule_type", "now")
    raw_workflow_id = body.get("workflow_id")

    if schedule_type == "now":
        from apps.core.scans.pipeline import create_scan_session
        from apps.core.scans.tasks import run_scan_task

        workflow = None
        if raw_workflow_id is not None:
            from apps.core.workflows.models import Workflow

            try:
                workflow = Workflow.objects.get(pk=int(raw_workflow_id))
            except (ValueError, TypeError):
                return api_response(errors={"workflow_id": ["Must be an integer."]}, status=400)
            except Workflow.DoesNotExist:
                return api_response(errors={"workflow_id": ["Workflow not found."]}, status=404)

        session = create_scan_session(domain, workflow=workflow)
        if session is None:
            return api_response(
                errors={"domain": ["A scan is already running for this domain."]},
                status=409,
            )
        run_scan_task(session.id)
        return api_response(data={"uuid": str(session.uuid)}, status=201)

    elif schedule_type == "once":
        raw_scheduled_at = body.get("scheduled_at", "")
        try:
            scheduled_at = datetime.datetime.fromisoformat(raw_scheduled_at)
        except (ValueError, TypeError):
            return api_response(
                errors={"scheduled_at": ["Invalid ISO datetime format."]}, status=400
            )
        _schedule_once(domain, scheduled_at)
        return api_response(data={"scheduled_at": scheduled_at.isoformat()})

    elif schedule_type == "recurring":
        recurrence = body.get("recurrence", "daily")
        raw_time = body.get("recurrence_time", "00:00")
        try:
            recurrence_time = datetime.datetime.strptime(raw_time, "%H:%M").time()
        except (ValueError, TypeError):
            return api_response(
                errors={"recurrence_time": ["Expected HH:MM format."]}, status=400
            )
        _schedule_recurring(domain, recurrence, recurrence_time)
        return api_response(data={"recurrence": recurrence})

    return api_response(
        errors={"schedule_type": ["Must be 'now', 'once', or 'recurring'."]}, status=400
    )


@api_login_required
def api_scan_detail(request, session_uuid):
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    vuln_counts = _get_vuln_counts(session)

    from apps.core.assets.models import IPAddress, Port, Subdomain
    from apps.core.findings.models import Finding
    from apps.core.web_assets.models import URL

    subdomains = list(
        Subdomain.objects.filter(session=session).order_by("-is_active", "subdomain")
    )
    ips = list(
        IPAddress.objects.filter(session=session)
        .select_related("subdomain")
        .order_by("address")
    )
    ports = list(
        Port.objects.filter(session=session)
        .select_related("ip_address")
        .order_by("address", "port")
    )
    urls = list(
        URL.objects.filter(session=session)
        .select_related("port", "subdomain")
        .order_by("url")
    )
    nmap_findings = list(
        Finding.objects.filter(session=session, source="nmap")
        .select_related("port")
        .order_by("-discovered_at")
    )
    domain_findings = list(
        Finding.objects.filter(session=session, source="domain_security")
        .select_related("subdomain")
        .order_by("-severity", "-discovered_at")
    )
    other_findings = list(
        Finding.objects.filter(session=session)
        .exclude(source__in=["nmap", "domain_security"])
        .select_related("port", "url")
        .order_by("-discovered_at")
    )

    return api_response(
        data={
            "session": serialize_scan_session(session),
            "vuln_counts": vuln_counts,
            "subdomains": [serialize_subdomain(s) for s in subdomains],
            "ips": [serialize_ip(i) for i in ips],
            "ports": [serialize_port(p) for p in ports],
            "urls": [serialize_url(u) for u in urls],
            "nmap_findings": [serialize_finding(f) for f in nmap_findings],
            "domain_findings": [serialize_finding(f) for f in domain_findings],
            "other_findings": [serialize_finding(f) for f in other_findings],
            "asset_counts": {
                "subdomains_total": len(subdomains),
                "subdomains_active": sum(1 for s in subdomains if s.is_active),
                "ips": len(ips),
                "ports": len(ports),
                "urls": len(urls),
                "nmap_findings": len(nmap_findings),
            },
        }
    )


@api_login_required
def api_scan_status(request, session_uuid):
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    vuln_counts = _get_vuln_counts(session)

    from apps.core.assets.models import IPAddress, Port, Subdomain
    from apps.core.findings.models import Finding
    from apps.core.web_assets.models import URL

    sub_agg = Subdomain.objects.filter(session=session).aggregate(
        total=Count("id"),
        active=Count("id", filter=Q(is_active=True)),
    )
    asset_counts = {
        "subdomains_total": sub_agg["total"],
        "subdomains_active": sub_agg["active"],
        "ips": IPAddress.objects.filter(session=session).count(),
        "ports": Port.objects.filter(session=session).count(),
        "urls": URL.objects.filter(session=session).count(),
        "nmap_findings": Finding.objects.filter(session=session, source="nmap").count(),
    }

    step_results = []
    try:
        run = session.workflow_run
        step_results = list(run.step_results.order_by("order"))
    except Exception:
        pass

    return api_response(
        data={
            "session": {
                "uuid": str(session.uuid),
                "status": session.status,
                "domain_name": session.domain,
            },
            "vuln_counts": vuln_counts,
            "asset_counts": asset_counts,
            "step_results": [serialize_workflow_step_result(sr) for sr in step_results],
        }
    )


@api_login_required
def api_scan_stop(request, session_uuid):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    session = get_object_or_404(ScanSession, uuid=session_uuid)
    if session.status in ("pending", "running"):
        session.status = "cancelled"
        session.end_time = timezone.now()
        session.save(update_fields=["status", "end_time"])
        logger.info(f"Scan cancelled via API: session={session.id} domain={session.domain}")

    return api_response(data={"status": session.status})


@api_login_required
def api_scan_delete(request, session_uuid):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    session = get_object_or_404(ScanSession, uuid=session_uuid)
    session.delete()
    logger.info(f"Scan deleted via API: uuid={session_uuid}")

    _rebuild_finding_type_summaries()

    return api_response(data={"deleted": str(session_uuid)})


@api_login_required
def api_vulnerability_list(request):
    from apps.core.findings.models import Finding

    severity = request.GET.get("severity", "").strip()
    domain = request.GET.get("domain", "").strip()
    status_filter = request.GET.get("status", "").strip()
    source_filter = request.GET.get("source", "").strip()
    raw_session_id = request.GET.get("session_id", "").strip()
    try:
        session_id = int(raw_session_id) if raw_session_id else None
    except ValueError:
        session_id = None

    latest_ids = latest_session_ids()

    base_qs = Finding.objects.select_related("session")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=latest_ids)

    # Summary card counts — always across latest sessions, open status only
    count_open_critical = Finding.objects.filter(
        session_id__in=latest_ids, status="open", severity="critical"
    ).count()
    count_open_high = Finding.objects.filter(
        session_id__in=latest_ids, status="open", severity="high"
    ).count()
    count_open_medium = Finding.objects.filter(
        session_id__in=latest_ids, status="open", severity="medium"
    ).count()
    count_open_low = Finding.objects.filter(
        session_id__in=latest_ids, status="open", severity="low"
    ).count()

    qs = base_qs.order_by(
        models.Case(
            models.When(severity="critical", then=0),
            models.When(severity="high", then=1),
            models.When(severity="medium", then=2),
            models.When(severity="low", then=3),
            default=4,
            output_field=models.IntegerField(),
        ),
        "-discovered_at",
    )

    if severity:
        qs = qs.filter(severity=severity)
    if session_id:
        qs = qs.filter(session_id=session_id)
    if domain:
        qs = qs.filter(session__domain__icontains=domain)
    if status_filter:
        qs = qs.filter(status=status_filter)
    if source_filter:
        qs = qs.filter(source=source_filter)

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    return api_response(
        data={
            "findings": [serialize_finding(f) for f in page],
            "counts": {
                "open_critical": count_open_critical,
                "open_high": count_open_high,
                "open_medium": count_open_medium,
                "open_low": count_open_low,
            },
        },
        pagination={
            "page": page.number,
            "total_pages": paginator.num_pages,
            "count": paginator.count,
            "has_next": page.has_next(),
            "has_previous": page.has_previous(),
        },
    )


@api_login_required
def api_finding_update_status(request, finding_id):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    from apps.core.findings.models import Finding, STATUS_CHOICES

    finding = get_object_or_404(Finding, id=finding_id)

    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return api_response(errors={"detail": ["Invalid JSON body."]}, status=400)

    new_status = (body.get("status") or "").strip()
    valid_statuses = {s[0] for s in STATUS_CHOICES}
    if new_status not in valid_statuses:
        return api_response(
            errors={"status": [f"Must be one of: {', '.join(sorted(valid_statuses))}."]},
            status=400,
        )

    finding.status = new_status
    if new_status == "resolved" and not finding.resolved_at:
        finding.resolved_at = timezone.now()
    elif new_status != "resolved":
        finding.resolved_at = None

    assigned_to = body.get("assigned_to")
    if assigned_to is not None:
        finding.assigned_to = str(assigned_to)[:150]

    resolution_note = body.get("resolution_note")
    if resolution_note is not None:
        finding.resolution_note = str(resolution_note)[:5000]

    finding.save(update_fields=["status", "resolved_at", "assigned_to", "resolution_note"])

    return api_response(data=serialize_finding(finding))


@api_login_required
def api_scheduled_list(request):
    from apps.core.scheduler import get_scheduler

    jobs = []
    try:
        all_jobs = get_scheduler().get_jobs()
        jobs = [p for job in all_jobs if (p := _parse_job(job)) is not None]
        jobs.sort(
            key=lambda j: (
                0 if j["job_type"] == "recurring" else 1,
                j["next_run_time"] or datetime.datetime.max.replace(tzinfo=datetime.timezone.utc),
            )
        )
    except Exception:
        logger.exception("[api_scheduled_list] Failed to fetch scheduled jobs")

    serialized = [
        {
            "job_id": j["job_id"],
            "domain": j["domain"],
            "job_type": j["job_type"],
            "frequency": j["frequency"],
            "next_run_time": j["next_run_time"].isoformat() if j["next_run_time"] is not None else None,
        }
        for j in jobs
    ]
    return api_response(data=serialized)


@api_login_required
def api_scheduled_cancel(request, job_id):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    if not (job_id.startswith("once_") or job_id.startswith("recurring_")):
        return api_response(
            errors={"job_id": ["Invalid job ID. Must start with 'once_' or 'recurring_'."]},
            status=400,
        )

    from apps.core.scheduler import get_scheduler
    from apscheduler.jobstores.base import JobLookupError

    note = None
    try:
        get_scheduler().remove_job(job_id)
        logger.info(f"Scheduled job cancelled via API: {job_id}")
    except JobLookupError:
        logger.info(f"Job already gone (may have already run): {job_id}")
        note = "Job already completed or was already cancelled."

    result = {"cancelled": job_id}
    if note:
        result["note"] = note
    return api_response(data=result)
