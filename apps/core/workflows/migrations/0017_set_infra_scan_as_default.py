"""Set Infra Scan as the default workflow, demote Full Scan."""

from django.db import migrations


def set_infra_scan_default(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Full Scan").update(is_default=False)
    Workflow.objects.filter(name="Infra Scan").update(is_default=True)


def revert(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Infra Scan").update(is_default=False)
    Workflow.objects.filter(name="Full Scan").update(is_default=True)


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0016_create_infra_scan_workflow"),
    ]

    operations = [
        migrations.RunPython(set_infra_scan_default, revert),
    ]
