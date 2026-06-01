from django.apps import AppConfig


class TakeoverCheckConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.takeover_check"
    label = "takeover_check"
    verbose_name = "Subdomain Takeover Check"
    tool_meta = {
        "label": "Subdomain Takeover Check",
        "runner": "apps.takeover_check.scanner.run_takeover_check",
        "phase": 3.5,
        "requires": ["dnsx"],
        "produces_findings": True,
    }
