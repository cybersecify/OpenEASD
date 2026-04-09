"""
Workflow runner — executes a Workflow's steps for a ScanSession,
recording per-step status, timing, and finding counts.
"""

import logging

from django.utils import timezone as django_tz

from .models import WorkflowRun, WorkflowStepResult

logger = logging.getLogger(__name__)

# Maps tool name → (runner function, result counter)
_TOOL_RUNNERS = {
    "dns_analyzer": ("apps.dns_analyzer.scanner", "run_dns_analysis"),
    "ssl_checker": ("apps.ssl_checker.scanner", "run_ssl_check"),
    "email_security": ("apps.email_security.scanner", "run_email_check"),
    "subfinder": ("apps.subfinder.scanner", "run_subfinder"),
    "naabu": ("apps.naabu.scanner", "run_naabu"),
    "nmap": ("apps.nmap.scanner", "run_nmap"),
    "nuclei": ("apps.nuclei.scanner", "run_nuclei"),
}

# Tools that need a 'targets' list (built from subfinder output)
_NEEDS_TARGETS = {"naabu", "nuclei"}
# Tools that only need domain
_DOMAIN_ONLY = {"dns_analyzer", "ssl_checker", "email_security", "nmap"}


def run_workflow(workflow_run_id: int):
    """Execute all steps of a WorkflowRun in order."""
    run = WorkflowRun.objects.select_related("workflow", "session").get(id=workflow_run_id)
    session = run.session
    domain = session.domain

    run.status = "running"
    run.started_at = django_tz.now()
    run.save(update_fields=["status", "started_at"])

    tools = run.workflow.enabled_tools()
    subdomains = []  # populated by subfinder, used by naabu/nuclei

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
                module_path, func_name = _TOOL_RUNNERS[tool]
                import importlib
                module = importlib.import_module(module_path)
                fn = getattr(module, func_name)

                if tool in _NEEDS_TARGETS:
                    targets = [domain] + [s.subdomain for s in subdomains]
                    results = fn(session, targets)
                elif tool in _DOMAIN_ONLY:
                    results = fn(session)
                elif tool == "subfinder":
                    results = fn(session)
                    subdomains = results  # save for downstream tools
                else:
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

        run.status = "completed"

    except Exception as exc:
        logger.error(f"[workflow:{run.id}] Run failed: {exc}", exc_info=True)
        run.status = "failed"

    run.finished_at = django_tz.now()
    run.save(update_fields=["status", "finished_at"])
