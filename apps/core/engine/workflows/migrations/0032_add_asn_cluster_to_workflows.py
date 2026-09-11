"""Add asn_cluster (Lookalike ASN Clustering) to the default workflows.

asn_cluster is a passive, phase-12 correlation tool: it reads typosquat's
`lookalike_domain` findings, resolves their IPs to ASNs (Team Cymru, keyless),
and groups lookalikes that share hosting infrastructure into campaign findings.
It joins:

  * Full Scan    — the invariant test_full_scan_covers_every_registered_tool
                   requires every non-core registered tool to be in the default
                   Full Scan.
  * Passive Scan — it is passive (active=False) and depends on typosquat, which
                   is already in Passive Scan, so it belongs in the no-auth
                   passive recon workflow too.

Additive and idempotent (skips if already present), matching 0029/0030/0031.
Execution order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

_TOOL = "asn_cluster"
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
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    for name in _WORKFLOWS:
        wf = Workflow.objects.filter(name=name).first()
        if wf is None:
            continue
        WorkflowStep.objects.filter(workflow=wf, tool=_TOOL).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0031_split_domain_security_probe"),
    ]

    operations = [
        migrations.RunPython(add_tool, remove_tool),
    ]
