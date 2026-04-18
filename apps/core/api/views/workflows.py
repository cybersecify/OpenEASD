"""API views for Workflow CRUD and step management."""

import json
import logging
from json import JSONDecodeError

from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from apps.core.api.decorators import api_login_required
from apps.core.api.serializers import api_response, serialize_workflow, serialize_workflow_step_result
from apps.core.workflows.models import Workflow, WorkflowStep
from apps.core.workflows.registry import get_tool_choices, get_tool_requires, get_tool_phases

logger = logging.getLogger(__name__)


@api_login_required
def api_workflow_tools(request):
    """Returns all registered tool choices — used by create workflow form."""
    if request.method != "GET":
        return api_response(errors="Method not allowed", status=405)
    tools = [
        {"key": key, "label": label, "phase": get_tool_phases().get(key, 99)}
        for key, label in get_tool_choices()
    ]
    return api_response({
        "tools": tools,
        "requires": get_tool_requires(),  # dict: {tool: [dep_tools]}
    })


@api_login_required
def api_workflow_list(request):
    if request.method != "GET":
        return api_response(errors="Method not allowed", status=405)
    workflows = Workflow.objects.prefetch_related("steps")
    return api_response([serialize_workflow(w) for w in workflows])


@api_login_required
def api_workflow_create(request):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    try:
        body = json.loads(request.body)
    except JSONDecodeError:
        return api_response(errors="Invalid JSON", status=400)

    name = (body.get("name") or "").strip()
    description = (body.get("description") or "").strip()
    is_default = bool(body.get("is_default", False))
    tools = body.get("tools") or []

    if not name:
        return api_response(errors={"name": ["This field is required."]}, status=400)

    valid_tools = {key for key, _ in get_tool_choices()}
    invalid = [t for t in tools if t not in valid_tools]
    if invalid:
        return api_response(errors={"tools": [f"Unknown tools: {invalid}"]}, status=400)

    tool_phases = get_tool_phases()
    workflow = Workflow.objects.create(
        name=name,
        description=description,
        is_default=is_default,
    )
    for tool in tools:
        WorkflowStep.objects.create(
            workflow=workflow,
            tool=tool,
            order=tool_phases.get(tool, 99),
            enabled=True,
        )

    return api_response(serialize_workflow(workflow), status=201)


@api_login_required
def api_workflow_detail(request, pk):
    workflow = get_object_or_404(
        Workflow.objects.prefetch_related("steps", "runs__step_results"), pk=pk
    )
    tool_choices = get_tool_choices()
    tool_phases = get_tool_phases()
    enabled_tools = {s.tool: s.enabled for s in workflow.steps.all()}
    tool_steps = [
        {"key": key, "label": label, "enabled": enabled_tools.get(key, False), "phase": tool_phases.get(key, 99)}
        for key, label in tool_choices
    ]

    recent_runs = workflow.runs.select_related("session").order_by("-started_at")[:10]

    return api_response({
        "workflow": serialize_workflow(workflow),
        "tool_steps": tool_steps,
        "tool_requires": get_tool_requires(),
        "recent_runs": [
            {
                "id": run.id,
                "uuid": str(run.uuid),
                "status": run.status,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "session_uuid": str(run.session.uuid) if run.session else None,
                "step_results": [serialize_workflow_step_result(sr) for sr in run.step_results.all()],
            }
            for run in recent_runs
        ],
    })


@api_login_required
def api_workflow_update(request, pk):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    workflow = get_object_or_404(Workflow, pk=pk)

    try:
        body = json.loads(request.body)
    except JSONDecodeError:
        return api_response(errors="Invalid JSON", status=400)

    name = (body.get("name") or "").strip()
    description = (body.get("description") or "").strip()
    is_default = bool(body.get("is_default", False))
    tools = body.get("tools") or []

    if not name:
        return api_response(errors={"name": ["This field is required."]}, status=400)

    valid_tools = {key for key, _ in get_tool_choices()}
    invalid = [t for t in tools if t not in valid_tools]
    if invalid:
        return api_response(errors={"tools": [f"Unknown tools: {invalid}"]}, status=400)

    tool_phases = get_tool_phases()
    workflow.name = name
    workflow.description = description
    workflow.is_default = is_default
    workflow.save()

    workflow.steps.all().delete()
    for tool in tools:
        WorkflowStep.objects.create(
            workflow=workflow,
            tool=tool,
            order=tool_phases.get(tool, 99),
            enabled=True,
        )

    return api_response(serialize_workflow(workflow))


@api_login_required
def api_workflow_delete(request, pk):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    workflow = get_object_or_404(Workflow, pk=pk)
    name = workflow.name
    workflow.delete()
    return api_response({"deleted": name})


@api_login_required
def api_workflow_toggle_step(request, pk, tool):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    workflow = get_object_or_404(Workflow, pk=pk)
    step, _ = WorkflowStep.objects.get_or_create(
        workflow=workflow,
        tool=tool,
        defaults={"order": get_tool_phases().get(tool, 99), "enabled": False},
    )
    step.enabled = not step.enabled
    step.save()
    return api_response({"tool": tool, "enabled": step.enabled})
