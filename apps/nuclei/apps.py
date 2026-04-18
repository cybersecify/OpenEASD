from django.apps import AppConfig


class NucleiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.nuclei"
    label = "nuclei"
    verbose_name = "Nuclei (Web Vuln Scan)"
    tool_meta = {
        "label": "Nuclei (Web Vuln Scan)",
        "runner": "apps.nuclei.scanner.run_nuclei",
        "phase": 9,
        "requires": ["httpx"],
        "produces_findings": True,
    }
