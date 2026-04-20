"""Workflows API router."""

import logging

from django.shortcuts import get_object_or_404

from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.api.auth import auth_bearer
from apps.core.workflows.models import Workflow, WorkflowStep
from apps.core.workflows.registry import get_tool_choices, get_tool_phases, get_tool_requires

logger = logging.getLogger(__name__)

router = Router(auth=auth_bearer)


def _serialize_workflow(workflow) -> dict:
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


@router.get("/tools/")
def list_tools(request):
    tools = [
        {"key": key, "label": label, "phase": get_tool_phases().get(key, 99)}
        for key, label in get_tool_choices()
    ]
    return {"tools": tools, "requires": get_tool_requires()}


@router.get("/")
def list_workflows(request):
    workflows = Workflow.objects.prefetch_related("steps")
    return [_serialize_workflow(w) for w in workflows]


class WorkflowIn(Schema):
    name: str
    description: str = ""
    is_default: bool = False
    tools: list[str] = []


@router.post("/create/", response={201: dict})
def create_workflow(request, data: WorkflowIn):
    name = data.name.strip()
    if not name:
        raise HttpError(400, "name is required")

    valid_tools = {key for key, _ in get_tool_choices()}
    invalid = [t for t in data.tools if t not in valid_tools]
    if invalid:
        raise HttpError(400, f"Unknown tools: {invalid}")

    tool_phases = get_tool_phases()
    workflow = Workflow.objects.create(
        name=name,
        description=data.description.strip(),
        is_default=data.is_default,
    )
    for tool in data.tools:
        WorkflowStep.objects.create(
            workflow=workflow,
            tool=tool,
            order=tool_phases.get(tool, 99),
            enabled=True,
        )
    return 201, _serialize_workflow(workflow)


@router.get("/{pk}/")
def get_workflow(request, pk: int):
    workflow = get_object_or_404(
        Workflow.objects.prefetch_related("steps", "runs__step_results"), pk=pk
    )
    tool_choices = get_tool_choices()
    tool_phases = get_tool_phases()
    enabled_tools = {s.tool: s.enabled for s in workflow.steps.all()}
    tool_steps = [
        {
            "key": key,
            "label": label,
            "enabled": enabled_tools.get(key, False),
            "phase": tool_phases.get(key, 99),
        }
        for key, label in tool_choices
    ]

    recent_runs = workflow.runs.select_related("session").order_by("-started_at")[:10]
    return {
        "workflow": _serialize_workflow(workflow),
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
                "step_results": [_serialize_step_result(sr) for sr in run.step_results.all()],
            }
            for run in recent_runs
        ],
    }


@router.post("/{pk}/update/")
def update_workflow(request, pk: int, data: WorkflowIn):
    workflow = get_object_or_404(Workflow, pk=pk)
    name = data.name.strip()
    if not name:
        raise HttpError(400, "name is required")

    valid_tools = {key for key, _ in get_tool_choices()}
    invalid = [t for t in data.tools if t not in valid_tools]
    if invalid:
        raise HttpError(400, f"Unknown tools: {invalid}")

    tool_phases = get_tool_phases()
    workflow.name = name
    workflow.description = data.description.strip()
    workflow.is_default = data.is_default
    workflow.save()

    workflow.steps.all().delete()
    for tool in data.tools:
        WorkflowStep.objects.create(
            workflow=workflow,
            tool=tool,
            order=tool_phases.get(tool, 99),
            enabled=True,
        )
    return _serialize_workflow(workflow)


@router.post("/{pk}/delete/")
def delete_workflow(request, pk: int):
    workflow = get_object_or_404(Workflow, pk=pk)
    name = workflow.name
    workflow.delete()
    return {"deleted": name}


@router.post("/{pk}/steps/{tool}/toggle/")
def toggle_step(request, pk: int, tool: str):
    workflow = get_object_or_404(Workflow, pk=pk)
    step, _ = WorkflowStep.objects.get_or_create(
        workflow=workflow,
        tool=tool,
        defaults={"order": get_tool_phases().get(tool, 99), "enabled": False},
    )
    step.enabled = not step.enabled
    step.save()
    return {"tool": tool, "enabled": step.enabled}
