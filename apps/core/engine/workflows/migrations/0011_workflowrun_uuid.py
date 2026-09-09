"""Add uuid field to WorkflowRun and populate existing rows."""

import uuid

from django.db import migrations, models


def populate_uuids(apps, schema_editor):
    WorkflowRun = apps.get_model("workflow", "WorkflowRun")
    for run in WorkflowRun.objects.all():
        run.uuid = uuid.uuid4()
        run.save(update_fields=["uuid"])


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0010_create_default_workflow"),
    ]

    operations = [
        # Step 1: Add uuid field, nullable, no unique constraint yet
        migrations.AddField(
            model_name="workflowrun",
            name="uuid",
            field=models.UUIDField(default=uuid.uuid4, null=True),
        ),
        # Step 2: Populate existing rows
        migrations.RunPython(populate_uuids, migrations.RunPython.noop),
        # Step 3: Make non-nullable and unique
        migrations.AlterField(
            model_name="workflowrun",
            name="uuid",
            field=models.UUIDField(default=uuid.uuid4, unique=True, editable=False),
        ),
        # Step 4: Add "partial" to status choices
        migrations.AlterField(
            model_name="workflowrun",
            name="status",
            field=models.CharField(
                max_length=20,
                choices=[
                    ("pending", "Pending"),
                    ("running", "Running"),
                    ("completed", "Completed"),
                    ("partial", "Partial"),
                    ("failed", "Failed"),
                ],
                default="pending",
                db_index=True,
            ),
        ),
    ]
