"""Add typosquat (Lookalike / Typosquat Domains) to the default workflows.

typosquat is a passive, Domain-Intelligence (phase 1) tool that generates
lookalike candidates from the apex domain and checks — via public DNS only —
which are registered / weaponizable (phishing infrastructure, brand abuse). It
never contacts the target. It joins:

  * Full Scan    — the invariant test_full_scan_covers_every_registered_tool
                   requires every non-core registered tool to be in the default
                   Full Scan, else the scan/report/README under-count.
  * Passive Scan — it is passive (active=False), so it belongs in the no-auth
                   passive recon workflow. Lookalike-domain intel is exactly the
                   "what threat surface already exists against your brand"
                   signal a passive report should surface, with no key and no
                   packet to the target.

Additive and idempotent (skips if already present), matching 0021/0023/0024/0025.
Execution order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

_TOOL = "typosquat"
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
        ("workflow", "0025_add_shodan_to_workflows"),
    ]

    operations = [
        migrations.RunPython(add_tool, remove_tool),
    ]
