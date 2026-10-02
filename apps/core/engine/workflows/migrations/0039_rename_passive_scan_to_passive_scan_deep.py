"""Rename the predefined 'Passive Scan' workflow to 'Passive Scan Deep'.

Pairs with 0038 (Quick Recon → Passive Scan Light): the two passive predefined
workflows now read as Light / Deep. Display-name only — membership (all passive
tools) is unchanged. Idempotent (exact-name match; 0 rows if already renamed) and
reversible. Runs AFTER the historical tool-add migrations (0024-0035) that
reference 'Passive Scan' by name, so those remain valid.
"""

from django.db import migrations

OLD_NAME = "Passive Scan"
NEW_NAME = "Passive Scan Deep"


def rename_forward(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name=OLD_NAME).update(name=NEW_NAME)


def rename_backward(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name=NEW_NAME).update(name=OLD_NAME)


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0038_rename_quick_recon_to_passive_scan_light"),
    ]

    operations = [
        migrations.RunPython(rename_forward, rename_backward),
    ]
