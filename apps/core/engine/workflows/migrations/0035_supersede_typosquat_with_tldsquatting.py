"""Supersede typosquat with tldsquatting in the default workflows.

The `typosquat` tool is retired and replaced by `tldsquatting` (same
`lookalike_domain` findings, broader TLD-permutation coverage). Remove every
`typosquat` WorkflowStep (Full Scan + Passive Scan, plus any custom workflow)
and add `tldsquatting` to Full Scan + Passive Scan — both passive, phase-1
"Brand Threat". Runs on deploy, cleaning existing DBs too.

Additive + idempotent for the add (skips if present), matching 0032/0034.
Reverse restores typosquat (for a clean downgrade; the app itself would also
need restoring to actually run). Execution order is unaffected — the runner
regroups steps by registry phase.
"""

from django.db import migrations

_OLD = "typosquat"
_NEW = "tldsquatting"
_WORKFLOWS = ["Full Scan", "Passive Scan"]


def _add(WorkflowStep, Workflow, tool, workflows):
    for name in workflows:
        wf = Workflow.objects.filter(name=name).first()
        if wf is None or wf.steps.filter(tool=tool).exists():
            continue
        next_order = (
            wf.steps.order_by("-order").values_list("order", flat=True).first() or 0
        ) + 1
        WorkflowStep.objects.create(workflow=wf, tool=tool, order=next_order, enabled=True)


def forward(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    WorkflowStep.objects.filter(tool=_OLD).delete()
    _add(WorkflowStep, Workflow, _NEW, _WORKFLOWS)


def backward(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    WorkflowStep.objects.filter(tool=_NEW).delete()
    _add(WorkflowStep, Workflow, _OLD, _WORKFLOWS)


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0034_readd_github_recon_to_workflows"),
    ]

    operations = [
        migrations.RunPython(forward, backward),
    ]
