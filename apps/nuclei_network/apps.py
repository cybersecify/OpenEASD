from django.apps import AppConfig


class NucleiNetworkConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.nuclei_network"
    label = "nuclei_network"
    verbose_name = "Nuclei Network"
    tool_meta = {
        "label": "Nuclei (Network Scan)",
        "runner": "apps.nuclei_network.scanner.run_nuclei_network",
        "phase": 8,
        "phase_group": "Network Exposure",
        "requires": ["naabu", "service_detection"],
        "produces_findings": True,
        "active": True,
    }
