from django.apps import AppConfig


class TlsCheckerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.tls_checker"
    label = "tls_checker"
    verbose_name = "TLS Checker"
    tool_meta = {
        "label": "TLS Checker",
        "runner": "apps.tls_checker.scanner.run_tls_check",
        "phase": 8,
        "phase_group": "Network Exposure",
        "requires": ["naabu", "service_detection"],
        "produces_findings": True,
        "active": True,
    }
