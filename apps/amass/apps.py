from django.apps import AppConfig


class AmassConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.amass"
    label = "amass"
    verbose_name = "Amass"
    tool_meta = {
        "label": "Amass",
        "runner": "apps.amass.scanner.run_amass",
        "phase": 2,
        "requires": [],
        "produces_findings": False,
    }
