"""Add shodan (Shodan passive exposure intelligence) to the default workflows.

shodan is a passive, Port-Discovery (phase 5) tool that reads Shodan's own
internet-wide scan dataset for the session's resolved public IPs — ports,
services, and known CVEs — without sending a packet to the target. It joins:

  * Full Scan    — the invariant test_full_scan_covers_every_registered_tool
                   requires every non-core registered tool to be in the default
                   Full Scan, else the scan/report/README under-count.
  * Passive Scan — it is passive (active=False), so it belongs in the no-auth
                   passive recon workflow. This is what powers the "what's already
                   publicly visible about you" free report without touching the
                   target: with no key it uses Shodan's free InternetDB endpoint.

Additive and idempotent (skips if already present), matching 0021/0023/0024.
Execution order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

_TOOL = "shodan"
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
        ("workflow", "0024_add_hudson_rock_to_workflows"),
    ]

    operations = [
        migrations.RunPython(add_tool, remove_tool),
    ]
