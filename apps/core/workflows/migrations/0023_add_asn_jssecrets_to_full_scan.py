"""Add asn_discovery + js_secrets to the Full Scan workflow.

Both tools were registered (#245, #248) but never added to the default Full
Scan, so the workflow-computed tool count (report + hosted scan) stayed at 19
while the registry had 21 — a claim/behaviour mismatch. Adding them here makes
"21 tools" true end to end: registry, Full Scan workflow, and report all agree.

Additive and idempotent (skips a tool already present), matching 0021. Execution
order is unaffected — the runner groups by registry phase, so appended steps run
in their correct phase regardless of `order`.
"""

from django.db import migrations

_NEW_TOOLS = ["asn_discovery", "js_secrets"]


def add_tools(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Full Scan").first()
    if wf is None:
        return
    existing = set(wf.steps.values_list("tool", flat=True))
    next_order = (wf.steps.order_by("-order").values_list("order", flat=True).first() or 0) + 1
    for tool in _NEW_TOOLS:
        if tool not in existing:
            WorkflowStep.objects.create(workflow=wf, tool=tool, order=next_order, enabled=True)
            next_order += 1


def remove_tools(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    wf = Workflow.objects.filter(name="Full Scan").first()
    if wf is None:
        return
    WorkflowStep.objects.filter(workflow=wf, tool__in=_NEW_TOOLS).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0022_create_passive_scan_workflow"),
    ]

    operations = [
        migrations.RunPython(add_tools, remove_tools),
    ]
