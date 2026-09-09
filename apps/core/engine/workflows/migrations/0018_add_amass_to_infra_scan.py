"""Add amass to Infra Scan workflow at order 3 (after subfinder), shift later steps down."""

from django.db import migrations
from django.db.models import F


def add_amass(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Infra Scan").first()
    if not wf:
        return

    # Shift all steps with order >= 3 down by one to make room for amass
    WorkflowStep.objects.filter(workflow=wf, order__gte=3).order_by("-order").update(
        order=F("order") + 1
    )
    WorkflowStep.objects.create(workflow=wf, tool="amass", order=3, enabled=True)


def remove_amass(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Infra Scan").first()
    if not wf:
        return

    WorkflowStep.objects.filter(workflow=wf, tool="amass").delete()
    # Shift steps back up
    WorkflowStep.objects.filter(workflow=wf, order__gte=3).order_by("order").update(
        order=F("order") - 1
    )


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0017_set_infra_scan_as_default"),
    ]

    operations = [
        migrations.RunPython(add_amass, remove_amass),
    ]
