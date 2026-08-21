from django.apps import AppConfig


class AsnDiscoveryConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.asn_discovery"
    label = "asn_discovery"
    verbose_name = "ASN / IP-range Discovery"
    tool_meta = {
        "label": "ASN / IP-range Discovery (amass intel)",
        "runner": "apps.asn_discovery.scanner.run_asn_discovery",
        "phase": 2,
        "phase_group": "Surface Enumeration",
        "requires": [],
        "produces_findings": True,
    }
