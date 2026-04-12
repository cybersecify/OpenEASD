from django.apps import AppConfig


class AlertsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.notifications"
    # Label kept as "alerts" for migration compatibility (folder was renamed from alerts/ to notifications/)
    label = "alerts"
    verbose_name = "Notifications"
