"""Add dns_history (Historical DNS Records) to the default workflows.

dns_history is a passive, Domain-Intelligence (phase 1) tool that queries a
passive-DNS dataset for a domain's historical A/AAAA/MX records and surfaces each
as an informational Finding (past hosting / stale records → recon + takeover
leads). It must join:

  * Full Scan    — the invariant test_full_scan_covers_every_registered_tool
                   requires every non-core registered tool to be in the default
                   Full Scan, else the scan/report/README under-count.
  * Passive Scan — it is passive (active=False): it queries a third-party dataset,
                   never the target, so it belongs in the no-auth passive recon
                   workflow.

Additive and idempotent (skips if already present), matching 0023/0029. Execution
order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

_TOOL = "dns_history"
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
        ("workflow", "0029_add_github_recon_to_workflows"),
    ]

    operations = [
        migrations.RunPython(add_tool, remove_tool),
    ]
