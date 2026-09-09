from django.apps import AppConfig


class CredentialsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.console.credentials"
    label = "credentials"
    verbose_name = "Credentials"
