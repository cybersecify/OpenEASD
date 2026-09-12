"""Seed the system-cron ScheduledJob rows (H7).

Idempotent (get_or_create by name), so it never clobbers an operator's enabled
toggle on re-apply. Cron strings mirror the deployed @DBOS.scheduled defaults;
they are informational (DBOS owns the actual tick). A missing row fails open, so
this seed is a convenience, not a correctness dependency.
"""

from django.db import migrations

_JOBS = [
    ("daily_scan", "0 2 * * *", "Daily full scan of authorized domains"),
    ("monitoring_sweep", "*/15 * * * *", "Per-domain monitoring sweep (due authorized domains)"),
    ("user_scans_sweep", "* * * * *", "Fire due user-created one-time/recurring scans"),
    ("watchdog", "*/15 * * * *", "Reap stuck scans + cancel phantom DBOS workflows"),
    ("token_purge", "0 3 * * *", "Delete expired blacklisted JWT tokens"),
    ("scan_prune", "30 3 * * *", "Prune old scan history (opt-in retention)"),
]


def seed(apps, schema_editor):
    ScheduledJob = apps.get_model("scans", "ScheduledJob")
    for name, cron, description in _JOBS:
        ScheduledJob.objects.get_or_create(
            name=name,
            defaults={"cron": cron, "enabled": True, "description": description},
        )


def unseed(apps, schema_editor):
    ScheduledJob = apps.get_model("scans", "ScheduledJob")
    ScheduledJob.objects.filter(name__in=[j[0] for j in _JOBS]).delete()


class Migration(migrations.Migration):
    dependencies = [("scans", "0016_scheduledjob")]
    operations = [migrations.RunPython(seed, unseed)]
