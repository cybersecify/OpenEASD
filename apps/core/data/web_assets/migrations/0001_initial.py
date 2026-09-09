"""Move URL model from assets to web_assets — reuses existing assets_url table."""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("assets", "0007_port_is_web"),
        ("scans", "0001_initial"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.CreateModel(
                    name="URL",
                    fields=[
                        ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                        ("url", models.CharField(max_length=2048)),
                        ("scheme", models.CharField(blank=True, max_length=10)),
                        ("host", models.CharField(blank=True, max_length=255)),
                        ("port_number", models.IntegerField(blank=True, null=True)),
                        ("status_code", models.IntegerField(blank=True, null=True)),
                        ("title", models.CharField(blank=True, max_length=500)),
                        ("web_server", models.CharField(blank=True, max_length=200)),
                        ("content_length", models.IntegerField(blank=True, null=True)),
                        ("source", models.CharField(max_length=50)),
                        ("discovered_at", models.DateTimeField(auto_now_add=True)),
                        ("port", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="urls", to="assets.port")),
                        ("session", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="urls", to="scans.scansession")),
                        ("subdomain", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="urls", to="assets.subdomain")),
                    ],
                    options={
                        "db_table": "assets_url",
                        "ordering": ["url"],
                        "unique_together": {("session", "url")},
                        "indexes": [
                            models.Index(fields=["host"], name="assets_url_host_df7654_idx"),
                            models.Index(fields=["status_code"], name="assets_url_status__a21c44_idx"),
                        ],
                    },
                ),
            ],
            database_operations=[],  # Table already exists as assets_url
        ),
    ]
