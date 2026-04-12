import logging

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods

from django.contrib import messages

from .models import Workflow, WorkflowStep
from .registry import get_tool_choices, get_tool_requires, get_tool_phases

logger = logging.getLogger(__name__)


@login_required
def workflow_list(request):
    workflows = Workflow.objects.prefetch_related("steps")
    return render(request, "workflow/list.html", {"workflows": workflows})


@login_required
def workflow_detail(request, pk):
    workflow = get_object_or_404(Workflow.objects.prefetch_related("steps", "runs__step_results"), pk=pk)
    tool_choices = get_tool_choices()
    tool_phases = get_tool_phases()

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        is_default = request.POST.get("is_default") == "on"
        selected_tools = request.POST.getlist("tools")

        if name:
            workflow.name = name
            workflow.description = description
            workflow.is_default = is_default
            workflow.save()

            # Sync steps: delete old, create new
            workflow.steps.all().delete()
            for tool in selected_tools:
                WorkflowStep.objects.create(
                    workflow=workflow,
                    tool=tool,
                    order=tool_phases.get(tool, 99),
                    enabled=True,
                )
            messages.success(request, f"Workflow '{workflow.name}' saved.")
            return redirect("workflow-list")

    recent_runs = workflow.runs.select_related("session").order_by("-started_at")[:10]
    enabled_tools = {s.tool: s.enabled for s in workflow.steps.all()}
    tool_steps = [
        {"key": key, "label": label, "enabled": enabled_tools.get(key, False)}
        for key, label in tool_choices
    ]

    return render(request, "workflow/detail.html", {
        "workflow": workflow,
        "recent_runs": recent_runs,
        "tool_steps": tool_steps,
    })


@login_required
@require_http_methods(["GET", "POST"])
def workflow_create(request):
    tool_choices = get_tool_choices()
    tool_requires = get_tool_requires()
    tool_phases = get_tool_phases()

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        is_default = request.POST.get("is_default") == "on"
        selected_tools = request.POST.getlist("tools")

        if not name:
            return render(request, "workflow/create.html", {
                "tool_choices": tool_choices,
                "tool_requires_json": tool_requires,
                "error": "Workflow name is required.",
            })

        workflow = Workflow.objects.create(
            name=name,
            description=description,
            is_default=is_default,
        )
        for tool in selected_tools:
            WorkflowStep.objects.create(
                workflow=workflow,
                tool=tool,
                order=tool_phases.get(tool, 99),
                enabled=True,
            )

        messages.success(request, f"Workflow '{workflow.name}' created.")
        return redirect("workflow-list")

    return render(request, "workflow/create.html", {
        "tool_choices": tool_choices,
        "tool_requires_json": tool_requires,
    })


@login_required
@require_http_methods(["POST"])
def workflow_toggle_step(request, pk, tool):
    workflow = get_object_or_404(Workflow, pk=pk)
    tool_phases = get_tool_phases()
    step, _ = WorkflowStep.objects.get_or_create(
        workflow=workflow,
        tool=tool,
        defaults={"order": tool_phases.get(tool, 99)},
    )
    step.enabled = not step.enabled
    step.save(update_fields=["enabled"])
    return redirect("workflow-detail", pk=pk)


@login_required
@require_http_methods(["POST"])
def workflow_delete(request, pk):
    workflow = get_object_or_404(Workflow, pk=pk)
    name = workflow.name
    workflow.delete()
    messages.success(request, f"Workflow '{name}' deleted.")
    return redirect("workflow-list")
