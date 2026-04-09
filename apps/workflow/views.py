import logging

from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods

from .models import Workflow, WorkflowStep, TOOL_CHOICES

logger = logging.getLogger(__name__)

# Default tool order used when creating steps
_DEFAULT_ORDER = {tool: i for i, (tool, _) in enumerate(TOOL_CHOICES, start=1)}


def workflow_list(request):
    workflows = Workflow.objects.prefetch_related("steps")
    return render(request, "workflow/list.html", {"workflows": workflows})


def workflow_detail(request, pk):
    workflow = get_object_or_404(Workflow.objects.prefetch_related("steps", "runs__step_results"), pk=pk)
    recent_runs = workflow.runs.select_related("session").order_by("-started_at")[:10]
    return render(request, "workflow/detail.html", {
        "workflow": workflow,
        "recent_runs": recent_runs,
        "tool_choices": TOOL_CHOICES,
    })


@require_http_methods(["GET", "POST"])
def workflow_create(request):
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        is_default = request.POST.get("is_default") == "on"
        selected_tools = request.POST.getlist("tools")

        if not name:
            return render(request, "workflow/create.html", {
                "tool_choices": TOOL_CHOICES,
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
                order=_DEFAULT_ORDER.get(tool, 99),
                enabled=True,
            )

        return redirect("workflow-detail", pk=workflow.pk)

    return render(request, "workflow/create.html", {"tool_choices": TOOL_CHOICES})


@require_http_methods(["POST"])
def workflow_toggle_step(request, pk, tool):
    workflow = get_object_or_404(Workflow, pk=pk)
    step, _ = WorkflowStep.objects.get_or_create(
        workflow=workflow,
        tool=tool,
        defaults={"order": _DEFAULT_ORDER.get(tool, 99)},
    )
    step.enabled = not step.enabled
    step.save(update_fields=["enabled"])
    return redirect("workflow-detail", pk=pk)


@require_http_methods(["POST"])
def workflow_delete(request, pk):
    workflow = get_object_or_404(Workflow, pk=pk)
    workflow.delete()
    return redirect("workflow-list")
