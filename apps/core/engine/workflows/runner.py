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
    is safe to dispatch from a ThreadPoolExecutor worker. Postgres handles the
    concurrent WorkflowStepResult writes from parallel tool threads directly
    (each thread uses its own connection); tool runners are responsible for
    their own write safety.
    """
    from django.db import close_old_connections
    close_old_connections()
    from .registry import get_tool_produces_findings

    # Resume idempotency (F1b): the phase-group DBOS step re-runs the WHOLE group
    # on a crash-resume. Don't re-execute a tool that already reached a terminal
    # state, and reuse any non-terminal (crashed "running"/"pending") row rather
    # than creating a duplicate — WorkflowStepResult has no (run, tool) unique
    # constraint, so a naive create() would stack duplicates on every resume.
    existing = (
        WorkflowStepResult.objects.filter(run=run, tool=tool).order_by("id").first()
    )
    if existing is not None and existing.status in ("completed", "failed", "skipped"):
        return
    if existing is not None:
        step_result = existing
        step_result.order = order
        step_result.status = "running"
        step_result.started_at = django_tz.now()
        step_result.finished_at = None
        step_result.error = ""
        step_result.findings_count = 0
        step_result.save(update_fields=[
            "order", "status", "started_at", "finished_at", "error", "findings_count",
        ])
        # Idempotency (H5, pipeline principle #4): a non-terminal existing row means
        # this tool was interrupted mid-run (worker crash), so it is about to be
        # RE-executed. Finding writes use bulk_create (append, no unique constraint),
        # so any Findings the tool wrote before the crash would be DUPLICATED by the
        # re-run. Delete this tool's prior Findings for the session first, so the
        # re-run converges to the same state (delete-then-insert). source == the
        # registry tool key. Assets need no cleanup — they are (session, …)-unique
        # and written with ignore_conflicts=True, so re-writes are already idempotent.
        from apps.core.data.findings.models import Finding
        deleted, _ = Finding.objects.filter(session=session, source=tool).delete()
        if deleted:
            logger.info(
                "[workflow:%s] resume: cleared %d stale %s finding(s) before re-run",
                run.id, deleted, tool,
            )
    else:
        step_result = WorkflowStepResult.objects.create(
            run=run,
            tool=tool,
            order=order,
            status="running",
            started_at=django_tz.now(),
        )

    status = "completed"
    error_msg = ""
    findings_count = 0
    try:
        fn = _get_runner(tool)
        results = fn(session)
        count = len(results) if isinstance(results, (list, tuple)) else (results or 0)
        if get_tool_produces_findings().get(tool, False):
            findings_count = count
        # Asset-producing tools (subfinder, dnsx, naabu, httpx) return
        # Subdomain/IPAddress/Port/URL rows, not Findings. Surfacing their
        # list length as findings_count would falsely claim "subfinder: 10
        # findings" in API responses — so findings_count stays 0.
    except Exception as e:
        logger.error(f"[workflow:{run.id}] Step {tool} failed: {e}", exc_info=True)
        status = "failed"
        error_msg = str(e)

    step_result.status = status
    step_result.findings_count = findings_count
    step_result.error = error_msg
    step_result.finished_at = django_tz.now()
    step_result.save(update_fields=["status", "findings_count", "error", "finished_at"])


def resolve_phase_groups(workflow, only_tools: list | None = None) -> list:
    """The ordered list of phase groups a run will execute: enabled tools,
    filtered by only_tools, with service_detection auto-injected after naabu
    (full scans only), grouped by phase. Pure — no DB writes. Shared by
    run_workflow and the DBOS per-phase steps so both compute the same plan.
    """
    tools = workflow.enabled_tools()
    if only_tools is not None:
        tools = [t for t in tools if t in only_tools]
        for t in only_tools:
            if t not in tools:
                tools.append(t)

    if "service_detection" not in tools and "naabu" in tools and only_tools is None:
        insert_at = 0
        for i, t in enumerate(tools):
            if t == "naabu":
                insert_at = i + 1
                break
        tools.insert(insert_at, "service_detection")

    return _group_tools_by_phase(tools)


# Tools that are pure network I/O (DNS lookups / third-party API calls / small
# HTTP fetches) with no large memory footprint — safe to run concurrently even
# under LOW_MEMORY, unlike the RAM-hungry scanners (nuclei compiles ~13.5k
# templates into memory, amass brute-forces). This is what lets the phase-1
# intelligence group finish fast on a 1 GB box without risking an OOM. A group is
# only parallelised under low memory when EVERY tool in it is on this list.
_LOW_MEM_PARALLEL_SAFE = frozenset({
    "domain_security", "domain_probe", "typosquat", "dns_history",
    "hudson_rock", "breach_check", "github_secrets",
})


def run_one_phase_group(run, session, group: list, base_order: int) -> None:
    """Execute a single phase group. Sequential for one-tool groups; under
    LOW_MEMORY sequential too UNLESS every tool in the group is a light,
    network-I/O-only tool (``_LOW_MEM_PARALLEL_SAFE``) — those parallelise even on
    a small box. Otherwise concurrent. Extracted so the DBOS scan workflow can run
    one checkpointed group at a time."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from django.conf import settings

    # Resume (F1b): skip tools that already reached a terminal state this run, so a
    # crash-resume doesn't re-dispatch them. _run_single_step is the authoritative
    # guard; this just avoids spinning up threads/connections for already-done work.
    done = set(
        WorkflowStepResult.objects
        .filter(run=run, tool__in=group, status__in=("completed", "failed", "skipped"))
        .values_list("tool", flat=True)
    )
    group = [t for t in group if t not in done]
    if not group:
        return

    safe = getattr(settings, "SCAN_LOW_MEM_PARALLEL_SAFE", _LOW_MEM_PARALLEL_SAFE)
    low_mem = getattr(settings, "LOW_MEMORY", False)
    serialize = len(group) == 1 or (low_mem and not all(t in safe for t in group))

    if serialize:
        for i, tool in enumerate(group):
            _run_single_step(run, session, tool, base_order + i)
        return

    step_orders = {tool: base_order + i for i, tool in enumerate(group)}
    with ThreadPoolExecutor(max_workers=len(group)) as executor:
        futures = {
            executor.submit(_run_single_step, run, session, tool, step_orders[tool]): tool
            for tool in group
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                logger.error(
                    f"[workflow:{run.id}] Unexpected error in parallel step future: {exc}",
                    exc_info=True,
                )


def run_workflow(workflow_run_id: int, only_tools: list | None = None):
    """Execute all steps of a WorkflowRun, running same-phase tools concurrently.

    Tools are grouped by phase number. Within each group all tools start via
    ThreadPoolExecutor. The next group starts only after every tool in the
    current group finishes. Cancellation is checked between groups — a running
    phase always runs to completion before the cancellation takes effect.

    only_tools: if provided, restrict execution to these tool keys (subscan use-case).
    """
    run = WorkflowRun.objects.select_related("workflow", "session").get(id=workflow_run_id)
    session = run.session

    run.status = "running"
    run.started_at = django_tz.now()
    run.save(update_fields=["status", "started_at"])

    phase_groups = resolve_phase_groups(run.workflow, only_tools)
    cancelled = False
    order = 1

    try:
        for group_idx, group in enumerate(phase_groups):
            session.refresh_from_db(fields=["status"])
            if session.status == "cancelled":
                logger.info(f"[workflow:{run.id}] Scan cancelled — skipping remaining phases")
                for remaining_group in phase_groups[group_idx:]:
                    for tool in remaining_group:
                        WorkflowStepResult.objects.create(
                            run=run, tool=tool, order=order,
                            status="skipped",
                            started_at=django_tz.now(), finished_at=django_tz.now(),
                        )
                        order += 1
                cancelled = True
                break

            logger.info(f"[workflow:{run.id}] Starting phase group: {group}")
            run_one_phase_group(run, session, group, order)
            order += len(group)

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
