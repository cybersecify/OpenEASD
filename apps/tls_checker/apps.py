from django.apps import AppConfig


class TlsCheckerConfig(AppConfig):
    name = "apps.tls_checker"
    label = "tls_checker"
    verbose_name = "TLS Checker"
    tool_meta = {
        "label": "TLS Checker",
        "runner": "apps.tls_checker.scanner.run_tls_check",
        "phase": 7,
        "requires": ["naabu", "service_detection"],
        "produces_findings": True,
    }
