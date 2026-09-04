"""Add breach_check (data-breach exposure) to the default workflows.

breach_check is a passive, Domain-Intelligence (phase 1) tool that reports which
of an org's accounts / how many known breaches are associated with the target
domain, using third-party breach datasets (XposedOrNot's free catalog by default,
or Have I Been Pwned when a key is set). It sends no packet to the target. It
joins:

  * Full Scan    — the invariant test_full_scan_covers_every_registered_tool
                   requires every non-core registered tool to be in the default
                   Full Scan, else the scan/report/README under-count.
  * Passive Scan — it is passive (active=False), so it belongs in the no-auth
                   passive recon workflow; the free XposedOrNot tier needs no key.

Additive and idempotent (skips if already present), matching 0021/0023/0024/0025.
The tool self-skips gracefully when neither breach source returns data (no key +
XposedOrNot empty = no finding), so listing it in a workflow is always safe.
Execution order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

_TOOL = "breach_check"
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
