"""Remove URL from assets state — model moved to web_assets app."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0007_port_is_web"),
        ("web_assets", "0001_initial"),
        ("findings", "0006_alter_finding_url"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.DeleteModel(name="URL"),
            ],
            database_operations=[],  # Table stays — owned by web_assets now
        ),
    ]
