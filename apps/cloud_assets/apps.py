from django.apps import AppConfig


class CloudAssetsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.cloud_assets"
    label = "cloud_assets"
    verbose_name = "Cloud Assets"
    tool_meta = {
        "label": "Cloud Assets",
        "runner": "apps.cloud_assets.scanner.run_cloud_assets",
        "phase": 4,
        "phase_group": "Surface Enumeration",
        "requires": ["subfinder"],
        "produces_findings": True,
    }
