from django.apps import AppConfig


class NaabuConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.naabu"
    label = "naabu"
    verbose_name = "Naabu (Port Scan)"
    tool_meta = {
        "label": "Naabu (Port Scan)",
        "runner": "apps.naabu.scanner.run_naabu",
        "phase": 4,
        "requires": ["dnsx"],
        "produces_findings": False,
    }
