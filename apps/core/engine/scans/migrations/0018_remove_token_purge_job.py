"""Remove the obsolete ``token_purge`` ScheduledJob row.

The REST API + JWT auth were removed, so there are no JWT tokens to purge and the
cron is gone. Forward deletes the seeded row (0017 is left untouched, it is
already applied); reverse recreates it.
"""

from django.db import migrations


def remove(apps, schema_editor):
    ScheduledJob = apps.get_model("scans", "ScheduledJob")
    ScheduledJob.objects.filter(name="token_purge").delete()


def restore(apps, schema_editor):
    ScheduledJob = apps.get_model("scans", "ScheduledJob")
    ScheduledJob.objects.get_or_create(
        name="token_purge",
        defaults={
            "cron": "0 3 * * *",
            "enabled": True,
            "description": "Delete expired blacklisted JWT tokens",
        },
    )


class Migration(migrations.Migration):
    dependencies = [("scans", "0017_seed_scheduled_jobs")]
    operations = [migrations.RunPython(remove, restore)]
