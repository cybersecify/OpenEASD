from django.apps import AppConfig


class AssetInventoryConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.data.asset_inventory"
    label = "asset_inventory"
    verbose_name = "Asset Inventory"
