"""Add hudson_rock (Hudson Rock infostealer exposure) to the default workflows.

hudson_rock is a passive, Domain-Intelligence (phase 1) tool that queries Hudson
Rock's free keyless Cavalier API for a domain's infostealer-log exposure. It must
join:

  * Full Scan   — the invariant test_full_scan_covers_every_registered_tool
                  requires every non-core registered tool to be in the default
                  Full Scan, else the scan/report/README under-count.
  * Passive Scan — it is passive (active=False), sends no packets to the target,
                  so it belongs in the no-auth passive recon workflow.

Additive and idempotent (skips if already present), matching 0021/0023. Execution
order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

_TOOL = "hudson_rock"
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
        ("workflow", "0023_add_asn_jssecrets_to_full_scan"),
    ]

    operations = [
        migrations.RunPython(add_tool, remove_tool),
    ]
