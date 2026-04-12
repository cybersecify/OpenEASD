from django.apps import AppConfig


class NmapConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.nmap"
    label = "nmap"
    verbose_name = "Nmap (NSE Vuln Scan)"
    tool_meta = {
        "label": "Nmap (NSE Vuln Scan)",
        "runner": "apps.nmap.scanner.run_nmap",
        "phase": 6,
        "requires": ["naabu", "service_detection"],
        "produces_findings": True,
    }
