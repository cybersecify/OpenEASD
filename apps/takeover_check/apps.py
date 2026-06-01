from django.apps import AppConfig


class TakeoverCheckConfig(AppConfig):
    name = "apps.takeover_check"
    label = "takeover_check"
    verbose_name = "Subdomain Takeover Check"
    tool_meta = {
        "label": "Subdomain Takeover Check (subzy)",
        "runner": "apps.takeover_check.scanner.run_takeover_check",
        "phase": 4,
        "requires": ["subfinder"],
        "produces_findings": True,
    }
