from django.apps import AppConfig


class KatanaConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.katana"
    label = "katana"
    verbose_name = "Katana (URL Crawler)"
    tool_meta = {
        "label": "Katana",
        "runner": "apps.katana.scanner.run_katana",
        "phase": 9,
        "requires": ["httpx"],
        "produces_findings": False,
    }
