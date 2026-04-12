"""Remove service_detection step from default workflow — it's core, auto-injected."""

from django.db import migrations


def remove_service_detection(apps, schema_editor):
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    WorkflowStep.objects.filter(tool="service_detection").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0014_alter_workflowstep_tool_and_more"),
    ]

    operations = [
        migrations.RunPython(remove_service_detection, migrations.RunPython.noop),
    ]
