from django.apps import AppConfig


class CloudAssetsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.cloud_assets"
    label = "cloud_assets"
    verbose_name = "Cloud Asset Enumeration"
    tool_meta = {
        "label": "Cloud Asset Enumeration (cloud-enum)",
        "runner": "apps.cloud_assets.scanner.run_cloud_assets",
        "phase": 4,
        "phase_group": "Surface Enumeration",
        "requires": ["subfinder"],
        "produces_findings": True,
    }
