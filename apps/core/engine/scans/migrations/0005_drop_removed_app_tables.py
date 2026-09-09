"""
Drop tables for apps that have been permanently removed (dns_analyzer, email_security).
These tables have FK references to scans_scansession, so they must be removed to allow
clean cascade deletes.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0004_cleanup_model_fields"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[
                "DROP TABLE IF EXISTS dns_analyzer_dnsfinding;",
                "DROP TABLE IF EXISTS email_security_emailfinding;",
            ],
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
