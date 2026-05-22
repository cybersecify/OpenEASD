# Hand-authored migration to add the `partial` status to ScanSession.
# Pure choices change; no DB schema change.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0009_subscan_parent_and_tools"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scansession",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("running", "Running"),
                    ("completed", "Completed"),
                    ("partial", "Partial"),
                    ("cancelled", "Cancelled"),
                    ("failed", "Failed"),
                ],
                db_index=True,
                default="pending",
                max_length=20,
            ),
        ),
    ]
