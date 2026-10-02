"""Rename the predefined 'Quick Recon' workflow to 'Passive Scan Light'.

Only the workflow's display name changes — the membership (the four light passive
tools) and the `quick_recon` tool flag / `light_passive_tools()` helper are
unchanged. The new name shows in the scan-mode UI eyebrow, the scan history, and
reports. Idempotent (updates 0 rows if already renamed) and reversible.
"""

from django.db import migrations

OLD_NAME = "Quick Recon"
NEW_NAME = "Passive Scan Light"


def rename_forward(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name=OLD_NAME).update(name=NEW_NAME)


def rename_backward(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name=NEW_NAME).update(name=OLD_NAME)


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0037_create_active_light_workflow"),
    ]

    operations = [
        migrations.RunPython(rename_forward, rename_backward),
    ]
