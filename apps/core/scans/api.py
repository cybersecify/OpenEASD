"""Scans and scheduled jobs API routers."""

import datetime
import logging
import uuid

from django.core.paginator import Paginator
from django.db import models
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone


from ninja import Router, Schema, Status
from ninja.errors import HttpError

from apps.core.api.auth import JWTAuth
from apps.core.constants import SEVERITY_LEVELS
from apps.core.insights.builder import rebuild_finding_type_summaries
from apps.core.queries import latest_session_ids
from apps.core.scans.models import ScanSession

logger = logging.getLogger(__name__)

# RFC 1035 / RFC 1123 hostname validation (shared with domains/api.py)
import re as _re  # noqa: E402  (intentional: kept next to the pattern it compiles)
_VALID_HOSTNAME = _re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def _parse_schedule(sched):
    """Convert a ScheduledScan → API dict."""
    return {
        "job_id":        sched.job_id,
        "domain":        sched.domain,
        "job_type":      "recurring" if sched.kind == "recurring" else "one-time",
        "next_run_time": sched.next_run,
        "frequency":     sched.frequency or "—",
    }


def _schedule_once(domain, scheduled_at):
    """Schedule a one-time scan (ScheduledScan row; fired by the DBOS sweep)."""
    from apps.core.scans.models import ScheduledScan

    job_id = f"once_{domain}_{uuid.uuid4().hex}"
    ScheduledScan.objects.create(
        job_id=job_id, domain=domain, kind="once", frequency="—",
        next_run=scheduled_at,
    )
    logger.info(f"One-time scan scheduled: domain={domain} at={scheduled_at}")


def _schedule_recurring(domain, recurrence, recurrence_time):
    """Add or replace a recurring scan schedule (ScheduledScan row)."""
    from croniter import croniter
    from django.utils import timezone as _tz

    from apps.core.scans.models import ScheduledScan

    h, m = recurrence_time.hour, recurrence_time.minute
    cron = f"{m} {h} * * 1" if recurrence == "weekly" else f"{m} {h} * * *"
    job_id = f"recurring_{domain}"
    now = _tz.now()
    next_run = croniter(cron, now).get_next(type(now))

    ScheduledScan.objects.update_or_create(
        job_id=job_id,
        defaults={
            "domain": domain, "kind": "recurring", "cron": cron,
            "frequency": "Weekly (Mondays)" if recurrence == "weekly" else "Daily",
            "next_run": next_run, "enabled": True,
        },
    )
    logger.info(f"Recurring scan scheduled: domain={domain} recurrence={recurrence} time={recurrence_time}")


router = Router(auth=JWTAuth())
scheduled_router = Router(auth=JWTAuth())


# ---------------------------------------------------------------------------
# Serializer helpers
# ---------------------------------------------------------------------------

def _serialize_session_brief(session) -> dict:
    return {
        "id": session.id,
        "uuid": str(session.uuid),
        "domain_name": session.domain,
        "status": session.status,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "total_findings": session.total_findings,
    }


def _serialize_session(session) -> dict:
    return {
        "id": session.id,
        "uuid": str(session.uuid),
        "domain_name": session.domain,
        "scan_type": session.scan_type,
        "triggered_by": session.triggered_by,
        "workflow_id": session.workflow_id,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "status": session.status,
        "total_findings": session.total_findings,
        "coverage": {
            "waf_vendor": session.waf_vendor,
            "endpoints_probed": session.endpoints_probed,
            "endpoints_blocked": session.endpoints_blocked,
        },
    }


def _serialize_finding(finding) -> dict:
    return {
        "id": finding.id,
        "session_id": finding.session_id,
        "session_uuid": str(finding.session.uuid) if finding.session else None,
        "source": finding.source,
        "check_type": finding.check_type,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "remediation": finding.remediation,
        "target": finding.target,
        "extra": finding.extra,
        "discovered_at": finding.discovered_at.isoformat(),
        "status": finding.status,
        "assigned_to": finding.assigned_to,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "resolution_note": finding.resolution_note,
    }


def _serialize_subdomain(sub) -> dict:
    return {
        "id": sub.id,
        "domain": sub.domain,
        "subdomain": sub.subdomain,
        "source": sub.source,
        "is_active": sub.is_active,
        "resolved_at": sub.resolved_at.isoformat() if sub.resolved_at else None,
        "discovered_at": sub.discovered_at.isoformat(),
    }


def _serialize_ip(ip) -> dict:
    return {
        "id": ip.id,
        "address": ip.address,
        "version": ip.version,
        "source": ip.source,
        "discovered_at": ip.discovered_at.isoformat(),
        "subdomain_id": ip.subdomain_id,
    }


def _serialize_port(port) -> dict:
    return {
        "id": port.id,
        "address": port.address,
        "port": port.port,
        "protocol": port.protocol,
        "state": port.state,
        "service": port.service,
        "version": port.version,
        "is_web": port.is_web,
        "source": port.source,
        "discovered_at": port.discovered_at.isoformat(),
    }


def _serialize_url(url) -> dict:
    return {
        "id": url.id,
        "url": url.url,
        "scheme": url.scheme,
        "host": url.host,
        "port_number": url.port_number,
        "status_code": url.status_code,
        "title": url.title,
        "web_server": url.web_server,
        "content_length": url.content_length,
        "technologies": url.technologies or [],
        "source": url.source,
        "discovered_at": url.discovered_at.isoformat(),
    }


def _serialize_step_result(sr) -> dict:
    return {
        "tool": sr.tool,
        "status": sr.status,
        "order": sr.order,
        "started_at": sr.started_at.isoformat() if sr.started_at else None,
        "finished_at": sr.finished_at.isoformat() if sr.finished_at else None,
        "findings_count": sr.findings_count,
        "error": sr.error or None,
    }


def _get_vuln_counts(session) -> dict:
    from apps.core.findings.models import Finding

    counts = {sev: 0 for sev in SEVERITY_LEVELS}
    for row in Finding.objects.filter(session=session).values("severity").annotate(total=Count("id")):
        if row["severity"] in counts:
            counts[row["severity"]] = row["total"]
    return counts


def _is_passive_only_scan(schedule_type: str, workflow) -> bool:
    """True only for an immediate scan whose workflow contains solely passive tools.

    Passive tools use only public / third-party data and never touch the target,
    so such a scan needs no DomainAuthorization. Everything else — any active
    tool, or a scheduled (once/recurring) scan, which always runs the default
    active Full Scan workflow — is treated as active and stays behind the gate.

    Resolving to the DEFAULT workflow when none was chosen means a bare "now"
    scan (default = Full Scan) correctly reads as active and keeps the gate.
    """
    if schedule_type != "now":
        return False

    from apps.core.workflows.registry import is_passive_tool_set

    if workflow is None:
        from apps.core.workflows.models import Workflow
        workflow = Workflow.objects.filter(is_default=True).first()
        if workflow is None:
            return False  # defensive: no default → require auth

    return is_passive_tool_set(workflow.enabled_tools())


# ---------------------------------------------------------------------------
# Scans endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_scans(request, domain: str = "", status: str = "", page: int = 1):
    qs = ScanSession.objects.all().order_by("-start_time")
    if domain:
        qs = qs.filter(domain__icontains=domain)
    if status:
        qs = qs.filter(status=status)

    paginator = Paginator(qs, 25)
    p = paginator.get_page(page)
    return {
        "results": [_serialize_session_brief(s) for s in p],
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


class ScanStartRequest(Schema):
    domain: str
    schedule_type: str = "now"
    workflow_id: int | None = None
    scheduled_at: str | None = None
    recurrence: str = "daily"
    recurrence_time: str = "00:00"


@router.post("/start/", response={201: dict})
def start_scan(request, data: ScanStartRequest):
    domain = data.domain.strip().lower()
    if not domain:
        raise HttpError(400, "domain is required")
    if not _VALID_HOSTNAME.match(domain):
        raise HttpError(400, "Invalid domain name")

    # Resolve the workflow up front (immediate "now" scans only) so we can decide
    # whether authorization is required BEFORE the gate. A passive-only workflow
    # never sends packets to the target, so it needs no DomainAuthorization.
    workflow = None
    if data.schedule_type == "now" and data.workflow_id is not None:
        from apps.core.workflows.models import Workflow
        try:
            workflow = Workflow.objects.get(pk=data.workflow_id)
        except Workflow.DoesNotExist:
            raise HttpError(404, "Workflow not found")

    # Authorization gate — required unless this is an immediate passive-only scan.
    # Scheduled scans (once/recurring) always run the default active Full Scan
    # workflow and therefore always keep the gate.
    if not _is_passive_only_scan(data.schedule_type, workflow):
        from apps.core.domains.models import DomainAuthorization
        if not DomainAuthorization.objects.filter(domain__name=domain).exists():
            raise HttpError(403, "Domain is not authorized for scanning")

    if data.schedule_type == "now":
        from apps.core.scans.pipeline import create_scan_session
        from apps.core.scans.tasks import run_scan_task

        session = create_scan_session(domain, workflow=workflow)
        if session is None:
            raise HttpError(409, "A scan is already running for this domain.")
        run_scan_task(session.id)
        return Status(201, {"uuid": str(session.uuid)})

    elif data.schedule_type == "once":
        if not data.scheduled_at:
            raise HttpError(400, "scheduled_at is required for schedule_type=once")
        try:
            scheduled_at = datetime.datetime.fromisoformat(data.scheduled_at)
        except ValueError:
            raise HttpError(400, "Invalid ISO datetime format for scheduled_at")
        if scheduled_at.tzinfo is None:
            scheduled_at = timezone.make_aware(scheduled_at)
        _schedule_once(domain, scheduled_at)
        return Status(201, {"scheduled_at": scheduled_at.isoformat()})

    elif data.schedule_type == "recurring":
        if data.recurrence not in ("daily", "weekly"):
            raise HttpError(400, "recurrence must be 'daily' or 'weekly'")
        try:
            recurrence_time = datetime.datetime.strptime(data.recurrence_time, "%H:%M").time()
        except ValueError:
            raise HttpError(400, "recurrence_time must be HH:MM format")
        _schedule_recurring(domain, data.recurrence, recurrence_time)
        return Status(201, {"recurrence": data.recurrence})

    raise HttpError(400, "schedule_type must be 'now', 'once', or 'recurring'")


@router.get("/findings/")
def list_findings(
    request,
    severity: str = "",
    domain: str = "",
    status: str = "",
    source: str = "",
    session_id: int = 0,
    session_uuid: uuid.UUID | None = None,
    page: int = 1,
):
    from apps.core.findings.models import Finding

    # Allow callers to filter by scan UUID directly — matches list_urls and is
    # what most external clients have on hand. Internally still keyed by
    # session_id for the queries below.
    if session_uuid is not None and not session_id:
        session = get_object_or_404(ScanSession, uuid=str(session_uuid))
        session_id = session.id

    latest_ids = latest_session_ids()
    base_qs = Finding.objects.select_related("session")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=latest_ids)

    if session_id:
        count_base = Finding.objects.filter(session_id=session_id, status="open")
    else:
        count_base = Finding.objects.filter(session_id__in=latest_ids, status="open")
    count_open_critical = count_base.filter(severity="critical").count()
    count_open_high     = count_base.filter(severity="high").count()
    count_open_medium   = count_base.filter(severity="medium").count()
    count_open_low      = count_base.filter(severity="low").count()

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
    if status:
        qs = qs.filter(status=status)
    if source:
        qs = qs.filter(source=source)

    paginator = Paginator(qs, 25)
    p = paginator.get_page(page)

    return {
        "findings": [_serialize_finding(f) for f in p],
        "counts": {
            "open_critical": count_open_critical,
            "open_high": count_open_high,
            "open_medium": count_open_medium,
            "open_low": count_open_low,
        },
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


@router.get("/urls/")
def list_urls(
    request,
    domain: str = "",
    session_uuid: uuid.UUID | None = None,
    scheme: str = "",
    status_code: str = "",
    page: int = 1,
):
    from apps.core.web_assets.models import URL

    if session_uuid is not None:
        session = get_object_or_404(ScanSession, uuid=str(session_uuid))
        qs = URL.objects.filter(session=session)
    else:
        latest_ids = latest_session_ids()
        qs = URL.objects.filter(session_id__in=latest_ids)
        if domain:
            qs = qs.filter(session__domain__icontains=domain)

    if scheme:
        qs = qs.filter(scheme=scheme)
    if status_code:
        try:
            qs = qs.filter(status_code=int(status_code))
        except ValueError:
            pass

    qs = qs.select_related("port", "subdomain").order_by("url")
    paginator = Paginator(qs, 50)
    p = paginator.get_page(page)

    return {
        "results": [_serialize_url(u) for u in p],
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


class FindingStatusRequest(Schema):
    status: str
    assigned_to: str | None = None
    resolution_note: str | None = None


@router.post("/findings/{finding_id}/status/")
def update_finding_status(request, finding_id: int, data: FindingStatusRequest):
    from apps.core.findings.models import Finding, STATUS_CHOICES

    finding = get_object_or_404(Finding, id=finding_id)

    valid_statuses = {s[0] for s in STATUS_CHOICES}
    if data.status not in valid_statuses:
        raise HttpError(400, f"status must be one of: {', '.join(sorted(valid_statuses))}")

    finding.status = data.status
    if data.status == "resolved" and not finding.resolved_at:
        finding.resolved_at = timezone.now()
    elif data.status != "resolved":
        finding.resolved_at = None

    if data.assigned_to is not None:
        finding.assigned_to = str(data.assigned_to)[:150]
    if data.resolution_note is not None:
        finding.resolution_note = str(data.resolution_note)[:5000]

    finding.save(update_fields=["status", "resolved_at", "assigned_to", "resolution_note"])
    return _serialize_finding(finding)


@router.get("/{session_uuid}/")
def scan_detail(request, session_uuid: uuid.UUID):
    from apps.core.assets.models import IPAddress, Port, Subdomain
    from apps.core.findings.models import Finding
    from apps.core.web_assets.models import URL

    session = get_object_or_404(ScanSession, uuid=str(session_uuid))
    vuln_counts = _get_vuln_counts(session)

    subdomains = list(Subdomain.objects.filter(session=session).order_by("-is_active", "subdomain"))
    ips = list(IPAddress.objects.filter(session=session).select_related("subdomain").order_by("address"))
    ports = list(Port.objects.filter(session=session).select_related("ip_address").order_by("address", "port"))
    urls = list(URL.objects.filter(session=session).select_related("port", "subdomain").order_by("url"))

    # select_related("session"): _serialize_finding reads finding.session.uuid,
    # which would otherwise fire one query per finding (N+1) on this detail load.
    nmap_findings = list(
        Finding.objects.filter(session=session, source="nmap")
        .select_related("port", "session")
        .order_by("-discovered_at")
    )
    domain_findings = list(
        Finding.objects.filter(session=session, source="domain_security")
        .select_related("subdomain", "session")
        .order_by("-severity", "-discovered_at")
    )
    other_findings = list(
        Finding.objects.filter(session=session)
        .exclude(source__in=["nmap", "domain_security"])
        .select_related("port", "url", "session")
        .order_by("-discovered_at")
    )

    return {
        "session": _serialize_session(session),
        "vuln_counts": vuln_counts,
        "subdomains": [_serialize_subdomain(s) for s in subdomains],
        "ips": [_serialize_ip(i) for i in ips],
        "ports": [_serialize_port(p) for p in ports],
        "urls": [_serialize_url(u) for u in urls],
        "nmap_findings": [_serialize_finding(f) for f in nmap_findings],
        "domain_findings": [_serialize_finding(f) for f in domain_findings],
        "other_findings": [_serialize_finding(f) for f in other_findings],
        "asset_counts": {
            "subdomains_total": len(subdomains),
            "subdomains_active": sum(1 for s in subdomains if s.is_active),
            "ips": len(ips),
            "ports": len(ports),
            "urls": len(urls),
        },
    }


@router.get("/{session_uuid}/status/")
def scan_status(request, session_uuid: uuid.UUID):
    from apps.core.assets.models import IPAddress, Port, Subdomain
    from apps.core.web_assets.models import URL

    session = get_object_or_404(ScanSession, uuid=str(session_uuid))
    vuln_counts = _get_vuln_counts(session)

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
    }

    step_results = []
    try:
        run = session.workflow_run
        step_results = list(run.step_results.order_by("order"))
    except Exception:
        pass

    return {
        "session": {
            "uuid": str(session.uuid),
            "status": session.status,
            "domain_name": session.domain,
        },
        "vuln_counts": vuln_counts,
        "asset_counts": asset_counts,
        "step_results": [_serialize_step_result(sr) for sr in step_results],
    }


@router.post("/{session_uuid}/stop/")
def stop_scan(request, session_uuid: uuid.UUID):
    session = get_object_or_404(ScanSession, uuid=str(session_uuid))
    if session.status in ("pending", "running"):
        session.status = "cancelled"
        session.end_time = timezone.now()
        session.save(update_fields=["status", "end_time"])
        logger.info(f"Scan cancelled via API: session={session.id} domain={session.domain}")
    return {"status": session.status}


@router.post("/{session_uuid}/delete/")
def delete_scan(request, session_uuid: uuid.UUID):
    session = get_object_or_404(ScanSession, uuid=str(session_uuid))
    if session.status in ("pending", "running"):
        raise HttpError(409, "Cannot delete — scan is currently active. Stop it first.")
    session.delete()
    logger.info(f"Scan deleted via API: uuid={session_uuid}")
    rebuild_finding_type_summaries()
    return {"deleted": session_uuid}


class SubScanRequest(Schema):
    tools: list[str]


@router.post("/{session_uuid}/subscan/")
def start_subscan(request, session_uuid: uuid.UUID, data: SubScanRequest):
    from apps.core.scans.pipeline import create_subscan_session
    from apps.core.scans.tasks import run_scan_task
    from apps.core.workflows.registry import get_tool_runners

    if not data.tools:
        raise HttpError(400, "At least one tool is required")

    registered = set(get_tool_runners().keys())
    invalid = [t for t in data.tools if t not in registered]
    if invalid:
        raise HttpError(400, f"Unknown tools: {invalid}")

    # Authorization gate — a subscan is a scan. If any requested tool is active
    # it probes the parent scan's domain and requires DomainAuthorization. This
    # closes the loophole where a passive (unauthorized) parent scan could be
    # used to launch active tools against a target that never granted consent.
    from apps.core.workflows.registry import is_passive_tool_set
    if not is_passive_tool_set(data.tools):
        from apps.core.domains.models import DomainAuthorization
        parent = get_object_or_404(ScanSession, uuid=str(session_uuid))
        if not DomainAuthorization.objects.filter(domain__name=parent.domain).exists():
            raise HttpError(403, "Domain is not authorized for scanning")

    session = create_subscan_session(str(session_uuid), tools=data.tools)
    if session is None:
        raise HttpError(404, "Parent scan not found or not completed")

    run_scan_task(session.id)
    logger.info(f"Subscan started: parent={session_uuid} tools={data.tools} new_session={session.uuid}")
    return {"uuid": str(session.uuid)}


# ---------------------------------------------------------------------------
# Scheduled jobs endpoints
# ---------------------------------------------------------------------------

@scheduled_router.get("/")
def list_scheduled(request):
    from apps.core.scans.models import ScheduledScan

    jobs = []
    try:
        schedules = ScheduledScan.objects.filter(enabled=True)
        jobs = [_parse_schedule(s) for s in schedules]
        jobs.sort(
            key=lambda j: (
                0 if j["job_type"] == "recurring" else 1,
                j["next_run_time"] or datetime.datetime.max.replace(tzinfo=datetime.timezone.utc),
            )
        )
    except Exception:
        logger.exception("[list_scheduled] Failed to fetch scheduled jobs")

    return [
        {
            "job_id":        j["job_id"],
            "domain":        j["domain"],
            "job_type":      j["job_type"],
            "frequency":     j["frequency"],
            "next_run_time": j["next_run_time"].isoformat() if j["next_run_time"] else None,
        }
        for j in jobs
    ]


@scheduled_router.post("/{job_id}/cancel/")
def cancel_scheduled(request, job_id: str):
    if not (job_id.startswith("once_") or job_id.startswith("recurring_")):
        raise HttpError(400, "job_id must start with 'once_' or 'recurring_'")

    from apps.core.scans.models import ScheduledScan

    deleted, _ = ScheduledScan.objects.filter(job_id=job_id).delete()
    if deleted:
        logger.info(f"Scheduled job cancelled via API: {job_id}")
        note = None
    else:
        logger.info(f"Job already gone: {job_id}")
        note = "Job already completed or was already cancelled."

    result = {"cancelled": job_id}
    if note:
        result["note"] = note
    return result
