from django.http import JsonResponse


def serialize_domain(domain) -> dict:
    last_scan_obj = getattr(domain, "last_scan", None)
    return {
        "id": domain.id,
        "name": domain.name,
        "is_primary": domain.is_primary,
        "is_active": domain.is_active,
        "added_at": domain.added_at.isoformat() if domain.added_at is not None else None,
        "last_scan": serialize_scan_session_brief(last_scan_obj) if last_scan_obj is not None else None,
        "findings_summary": getattr(domain, "findings_summary", {}),
    }


def serialize_scan_session(session) -> dict:
    return {
        "id": session.id,
        "uuid": str(session.uuid),
        "domain_name": session.domain,
        "scan_type": session.scan_type,
        "triggered_by": session.triggered_by,
        "workflow_id": session.workflow_id,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat() if session.end_time is not None else None,
        "status": session.status,
        "total_findings": session.total_findings,
    }


def serialize_scan_session_brief(session) -> dict:
    return {
        "id": session.id,
        "uuid": str(session.uuid),
        "domain_name": session.domain,
        "status": session.status,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat() if session.end_time is not None else None,
        "total_findings": session.total_findings,
    }


def serialize_finding(finding) -> dict:
    return {
        "id": finding.id,
        "session_id": finding.session_id,
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
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at is not None else None,
        "resolution_note": finding.resolution_note,
    }


def serialize_workflow(workflow) -> dict:
    steps = [
        {"tool": step.tool, "order": step.order, "enabled": step.enabled}
        for step in workflow.steps.all()
    ]
    return {
        "id": workflow.id,
        "name": workflow.name,
        "description": workflow.description,
        "is_default": workflow.is_default,
        "created_at": workflow.created_at.isoformat(),
        "updated_at": workflow.updated_at.isoformat(),
        "steps": steps,
    }


def serialize_workflow_step_result(step_result) -> dict:
    return {
        "tool": step_result.tool,
        "status": step_result.status,
        "order": step_result.order,
        "started_at": step_result.started_at.isoformat() if step_result.started_at is not None else None,
        "finished_at": step_result.finished_at.isoformat() if step_result.finished_at is not None else None,
        "findings_count": step_result.findings_count,
        "error": step_result.error or None,
    }


def serialize_port(port) -> dict:
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


def serialize_subdomain(sub) -> dict:
    return {
        "id": sub.id,
        "domain": sub.domain,
        "subdomain": sub.subdomain,
        "source": sub.source,
        "is_active": sub.is_active,
        "resolved_at": sub.resolved_at.isoformat() if sub.resolved_at is not None else None,
        "discovered_at": sub.discovered_at.isoformat(),
    }


def serialize_ip(ip) -> dict:
    return {
        "id": ip.id,
        "address": ip.address,
        "version": ip.version,
        "source": ip.source,
        "discovered_at": ip.discovered_at.isoformat(),
        "subdomain_id": ip.subdomain_id,
    }


def serialize_url(url) -> dict:
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
        "source": url.source,
        "discovered_at": url.discovered_at.isoformat(),
    }


def api_response(data=None, errors=None, status=200, pagination=None):
    return JsonResponse(
        {"ok": errors is None, "data": data, "errors": errors, "pagination": pagination},
        status=status,
    )
