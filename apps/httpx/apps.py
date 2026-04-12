from django.apps import AppConfig


class HttpxConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.httpx"
    label = "httpx"
    verbose_name = "HTTPx (Web Probe)"
    tool_meta = {
        "label": "HTTPx (Web Probe)",
        "runner": "apps.httpx.scanner.run_httpx",
        "phase": 6,
        "requires": ["naabu"],
        "produces_findings": False,
    }
