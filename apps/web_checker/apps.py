from django.apps import AppConfig


class WebCheckerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.web_checker"
    label = "web_checker"
    verbose_name = "Web Checker"
    tool_meta = {
        "label": "Web Checker",
        "runner": "apps.web_checker.scanner.run_web_check",
        "phase": 12,
        "phase_group": "Web Exposure",
        "requires": ["httpx"],
        "produces_findings": True,
        "active": True,
    }
