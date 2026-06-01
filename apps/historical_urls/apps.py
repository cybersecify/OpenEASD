from django.apps import AppConfig


class HistoricalUrlsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.historical_urls"
    label = "historical_urls"
    verbose_name = "Historical URLs (gau/waybackurls)"
    tool_meta = {
        "label": "Historical URLs (gau/waybackurls)",
        "runner": "apps.historical_urls.scanner.run_historical_urls",
        "phase": 8.5,
        "requires": ["httpx"],
        "produces_findings": False,
    }
