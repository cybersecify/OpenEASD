from django.apps import AppConfig


class WebCheckerConfig(AppConfig):
    name = "apps.web_checker"
    label = "web_checker"
    verbose_name = "Web Checker"
    tool_meta = {
        "label": "Web Checker",
        "runner": "apps.web_checker.scanner.run_web_check",
        "phase": 8,
        "requires": ["httpx"],
        "produces_findings": True,
    }
