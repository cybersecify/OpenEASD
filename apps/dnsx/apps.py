from django.apps import AppConfig


class DnsxConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.dnsx"
    label = "dnsx"
    verbose_name = "DNSx (Resolve)"
    tool_meta = {
        "label": "DNSx (Resolve)",
        "runner": "apps.dnsx.scanner.run_dnsx",
        "phase": 3,
        "phase_group": "Surface Enumeration",
        "requires": ["subfinder"],
        "produces_findings": False,
    }
