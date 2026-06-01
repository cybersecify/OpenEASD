from django.apps import AppConfig


class S3EnumConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.s3_enum"
    label = "s3_enum"
    verbose_name = "S3 Bucket Discovery"
    tool_meta = {
        "label": "S3 Bucket Discovery",
        "runner": "apps.s3_enum.scanner.run_s3_enum",
        "phase": 4.5,
        "requires": ["naabu"],
        "produces_findings": True,
    }
