"""Add github_recon (GitHub Org Recon) to the default workflows.

github_recon is a passive, Surface-Enumeration (phase 2) tool that enumerates the
target org's PUBLIC GitHub repos via GitHub's official REST API and surfaces exposed
infrastructure references (internal hostnames/subdomains, cloud-bucket URLs, API
endpoints) in that public code/config — widening the discovered attack surface from
source. It must join:

  * Full Scan    — the invariant test_full_scan_covers_every_registered_tool requires
                   every non-core registered tool to be in the default Full Scan,
                   else the scan/report/README under-count.
  * Passive Scan — it is passive (active=False): it queries GitHub's API, never the
                   target, so it belongs in the no-auth passive recon workflow. It
                   works keyless (unauthenticated GitHub API, request-capped), so the
                   Passive Scan stays fully self-serving with no key required.

Additive and idempotent (skips if already present), matching 0021/0023/0024/0025/0026.
Execution order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

_TOOL = "github_recon"
_WORKFLOWS = ["Full Scan", "Passive Scan"]


def add_tool(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    for name in _WORKFLOWS:
        wf = Workflow.objects.filter(name=name).first()
        if wf is None:
            continue
        if wf.steps.filter(tool=_TOOL).exists():
            continue
        next_order = (
            wf.steps.order_by("-order").values_list("order", flat=True).first() or 0
        ) + 1
        WorkflowStep.objects.create(workflow=wf, tool=_TOOL, order=next_order, enabled=True)


def remove_tool(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    for name in _WORKFLOWS:
        wf = Workflow.objects.filter(name=name).first()
        if wf is None:
            continue
        WorkflowStep.objects.filter(workflow=wf, tool=_TOOL).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0026_add_typosquat_to_workflows"),
    ]

    operations = [
        migrations.RunPython(add_tool, remove_tool),
    ]
