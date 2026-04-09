from django.apps import AppConfig


class EmailSecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.email_security"
    label = "email_security"
    verbose_name = "Email Security"
