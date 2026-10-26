"""Remove github_recon from all workflows (the tool app is being deleted).

github_recon (GitHub Org Recon — infra references in public repos) is retired.
Deleting the app removes it from the registry, but existing WorkflowStep rows
(added by 0029 to Full Scan + Passive Scan, plus any custom workflows) would
linger and reference a tool the runner no longer knows — so drop every step for
it here. Runs on deploy, cleaning the prod DB too.

Reverse re-adds it to Full Scan + Passive Scan (mirroring 0029) for a clean
downgrade, though the app itself would also need restoring to actually run.
"""

from django.db import migrations

_TOOL = "github_recon"
_WORKFLOWS = ["Full Scan", "Passive Scan"]


def remove_tool(apps, schema_editor):
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    WorkflowStep.objects.filter(tool=_TOOL).delete()


def readd_tool(apps, schema_editor):
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


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0032_add_asn_cluster_to_workflows"),
    ]

    operations = [
        migrations.RunPython(remove_tool, readd_tool),
    ]
