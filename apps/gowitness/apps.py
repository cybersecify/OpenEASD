from django.apps import AppConfig


class GowitnessConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.gowitness"
    label = "gowitness"
    verbose_name = "Gowitness (Screenshots)"
    tool_meta = {
        "label": "Gowitness (Screenshots)",
        "runner": "apps.gowitness.scanner.run_gowitness",
        "phase": 10,
        "requires": ["httpx"],
        "produces_findings": False,
    }
