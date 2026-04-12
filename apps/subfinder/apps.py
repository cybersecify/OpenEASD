from django.apps import AppConfig


class SubfinderConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.subfinder"
    label = "subfinder"
    verbose_name = "Subfinder"
    tool_meta = {
        "label": "Subfinder",
        "runner": "apps.subfinder.scanner.run_subfinder",
        "phase": 2,
        "requires": [],
        "produces_findings": False,
    }
