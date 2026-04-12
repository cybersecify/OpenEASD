"""Add service_detection step to default Full Scan workflow and update TOOL_CHOICES."""

from django.db import migrations, models


def add_service_detection(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Full Scan", is_default=True).first()
    if not wf:
        return

    # Bump httpx and later tools (order >= 5) up by 1
    WorkflowStep.objects.filter(workflow=wf, order__gte=5).update(
        order=models.F("order") + 1,
    )
    WorkflowStep.objects.create(
        workflow=wf, tool="service_detection", order=5, enabled=True,
    )


def remove_service_detection(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Full Scan", is_default=True).first()
    if not wf:
        return
    WorkflowStep.objects.filter(workflow=wf, tool="service_detection").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0011_workflowrun_uuid"),
    ]

    operations = [
        migrations.RunPython(add_service_detection, remove_service_detection),
    ]
