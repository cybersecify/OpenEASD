import uuid
from django.db import migrations, models


def populate_uuids(apps, schema_editor):
    ScanSession = apps.get_model("scans", "ScanSession")
    for session in ScanSession.objects.all():
        session.uuid = uuid.uuid4()
        session.save(update_fields=["uuid"])


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0002_scansession_workflow"),
    ]

    operations = [
        # Step 1: add without unique constraint
        migrations.AddField(
            model_name="scansession",
            name="uuid",
            field=models.UUIDField(default=uuid.uuid4, editable=False, null=True),
        ),
        # Step 2: populate unique UUIDs for existing rows
        migrations.RunPython(populate_uuids, migrations.RunPython.noop),
        # Step 3: enforce unique + not null
        migrations.AlterField(
            model_name="scansession",
            name="uuid",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
    ]
