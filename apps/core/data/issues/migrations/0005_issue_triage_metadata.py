from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("issues", "0004_alter_issue_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="issue",
            name="assigned_to",
            field=models.CharField(blank=True, max_length=150),
        ),
        migrations.AddField(
            model_name="issue",
            name="resolution_note",
            field=models.TextField(blank=True),
        ),
    ]
