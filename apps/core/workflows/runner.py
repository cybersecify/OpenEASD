"""
Workflow runner — executes a Workflow's steps for a ScanSession,
recording per-step status, timing, and finding counts.

Tool runners are auto-discovered from AppConfig.tool_meta via the registry.
"""

import importlib
import logging

from django.utils import timezone as django_tz

from .models import WorkflowRun, WorkflowStepResult

logger = logging.getLogger(__name__)


def _get_runner(tool_name: str):
    """Import and return the runner function for a tool from the registry."""
    from .registry import get_tool_runners

    runners = get_tool_runners()
    if tool_name not in runners:
        raise ValueError(f"Tool '{tool_name}' is not registered (no tool_meta in AppConfig)")

    runner_path = runners[tool_name]
    module_path, func_name = runner_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, func_name)


def run_workflow(workflow_run_id: int):
    """Execute all steps of a WorkflowRun in order."""
    run = WorkflowRun.objects.select_related("workflow", "session").get(id=workflow_run_id)
    session = run.session

    run.status = "running"
    run.started_at = django_tz.now()
    run.save(update_fields=["status", "started_at"])

    tools = run.workflow.enabled_tools()

    try:
        for order, tool in enumerate(tools, start=1):
            step_result = WorkflowStepResult.objects.create(
                run=run,
                tool=tool,
                order=order,
                status="running",
                started_at=django_tz.now(),
            )
            logger.info(f"[workflow:{run.id}] Running step {order}/{len(tools)}: {tool}")

            try:
                fn = _get_runner(tool)
                results = fn(session)
                count = len(results) if results else 0
                step_result.status = "completed"
                step_result.findings_count = count

            except Exception as e:
                logger.error(f"[workflow:{run.id}] Step {tool} failed: {e}", exc_info=True)
                step_result.status = "failed"
                step_result.error = str(e)

            step_result.finished_at = django_tz.now()
            step_result.save(update_fields=["status", "findings_count", "error", "finished_at"])

        # Check if any step failed — mark as partial failure
        if WorkflowStepResult.objects.filter(run=run, status="failed").exists():
            run.status = "partial"
        else:
            run.status = "completed"

    except Exception as exc:
        logger.error(f"[workflow:{run.id}] Run failed: {exc}", exc_info=True)
        run.status = "failed"

    run.finished_at = django_tz.now()
    run.save(update_fields=["status", "finished_at"])
