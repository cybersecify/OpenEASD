"""
Workflow runner — executes a Workflow's steps for a ScanSession,
recording per-step status, timing, and finding counts.

Tool runners are auto-discovered from AppConfig.tool_meta via the registry.
"""

import importlib
import logging
from itertools import groupby
from operator import itemgetter

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


def _group_tools_by_phase(tools: list) -> list:
    """Group a flat tool list into phase buckets, preserving intra-phase order.

    Returns [[phase_N_tools...], [phase_M_tools...], ...] sorted by phase number.
    Tools not in the registry default to phase 99 (run last).
    """
    from .registry import get_tool_phases
    phases = get_tool_phases()
    with_phase = [(t, phases.get(t, 99)) for t in tools]
    # Stable sort preserves the original intra-phase order from the workflow steps.
    with_phase.sort(key=itemgetter(1))
    return [
        [t for t, _ in group]
        for _, group in groupby(with_phase, key=itemgetter(1))
    ]


def _run_single_step(run, session, tool: str, order: int) -> None:
    """Execute one tool step, record its WorkflowStepResult, and persist timing.

    Calls close_old_connections() before touching the ORM so this function
    is safe to dispatch from a ThreadPoolExecutor worker in the future.
    """
    from django.db import close_old_connections
    close_old_connections()
    from .registry import get_tool_produces_findings

    step_result = WorkflowStepResult.objects.create(
        run=run,
        tool=tool,
        order=order,
        status="running",
        started_at=django_tz.now(),
    )
    try:
        fn = _get_runner(tool)
        results = fn(session)
        count = len(results) if isinstance(results, (list, tuple)) else (results or 0)
        step_result.status = "completed"
        if get_tool_produces_findings().get(tool, False):
            step_result.findings_count = count
        else:
            # Asset-producing tools (subfinder, dnsx, naabu, httpx) return
            # Subdomain/IPAddress/Port/URL rows, not Findings. Surfacing their
            # list length as findings_count would falsely claim "subfinder: 10
            # findings" in API responses.
            step_result.findings_count = 0
    except Exception as e:
        logger.error(f"[workflow:{run.id}] Step {tool} failed: {e}", exc_info=True)
        step_result.status = "failed"
        step_result.error = str(e)

    step_result.finished_at = django_tz.now()
    step_result.save(update_fields=["status", "findings_count", "error", "finished_at"])


def run_workflow(workflow_run_id: int, only_tools: list | None = None):
    """Execute all steps of a WorkflowRun in order.

    only_tools: if provided, restrict execution to these tool keys (subscan use-case).
    """
    run = WorkflowRun.objects.select_related("workflow", "session").get(id=workflow_run_id)
    session = run.session

    run.status = "running"
    run.started_at = django_tz.now()
    run.save(update_fields=["status", "started_at"])

    tools = run.workflow.enabled_tools()
    if only_tools is not None:
        tools = [t for t in tools if t in only_tools]
        for t in only_tools:
            if t not in tools:
                tools.append(t)

    # service_detection always runs after naabu (core infrastructure).
    # Skip for subscans (assets already classified from parent).
    if "service_detection" not in tools and only_tools is None:
        insert_at = 0
        for i, t in enumerate(tools):
            if t == "naabu":
                insert_at = i + 1
                break
        tools.insert(insert_at, "service_detection")

    cancelled = False
    try:
        for order, tool in enumerate(tools, start=1):
            session.refresh_from_db(fields=["status"])
            if session.status == "cancelled":
                logger.info(f"[workflow:{run.id}] Scan cancelled — stopping at step {order}")
                WorkflowStepResult.objects.create(
                    run=run, tool=tool, order=order,
                    status="skipped",
                    started_at=django_tz.now(), finished_at=django_tz.now(),
                )
                cancelled = True
                break

            logger.info(f"[workflow:{run.id}] Running step {order}/{len(tools)}: {tool}")
            _run_single_step(run, session, tool, order)

        if cancelled:
            run.status = "cancelled"
        elif WorkflowStepResult.objects.filter(run=run, status="failed").exists():
            run.status = "partial"
        else:
            run.status = "completed"

    except Exception as exc:
        logger.error(f"[workflow:{run.id}] Run failed: {exc}", exc_info=True)
        run.status = "failed"

    run.finished_at = django_tz.now()
    run.save(update_fields=["status", "finished_at"])
