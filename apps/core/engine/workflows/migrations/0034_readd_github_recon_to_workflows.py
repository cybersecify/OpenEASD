"""Re-add github_recon (GitHub Org Recon) to the default workflows.

github_recon was retired in migration 0033 (#438) and its app deleted. It is now
restored: a passive, phase-3 "Asset Discovery" tool that enumerates the target
org's PUBLIC GitHub repos and surfaces infrastructure references (internal
hostnames/subdomains, cloud-bucket URLs, API endpoints) leaked in that public
code/config. It joins:

  * Full Scan    — the invariant test_full_scan_covers_every_registered_tool
                   requires every non-core registered tool to be in the default
                   Full Scan.
  * Passive Scan — it is passive (active=False; only GitHub's public API is
                   touched, never the target), so it belongs in the no-auth
                   passive recon workflow too.

Additive and idempotent (skips if already present), matching 0029/0030/0031/0032.
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
        if wf is None or wf.steps.filter(tool=_TOOL).exists():
            continue
        next_order = (
            wf.steps.order_by("-order").values_list("order", flat=True).first() or 0
        ) + 1
        WorkflowStep.objects.create(workflow=wf, tool=_TOOL, order=next_order, enabled=True)


def remove_tool(apps, schema_editor):
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    WorkflowStep.objects.filter(tool=_TOOL).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0033_remove_github_recon"),
    ]

    operations = [
        migrations.RunPython(add_tool, remove_tool),
    ]
