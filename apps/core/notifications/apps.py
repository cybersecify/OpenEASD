from django.apps import AppConfig


class AlertsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.notifications"
    label = "alerts"
    verbose_name = "Alerts"
