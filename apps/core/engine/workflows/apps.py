from django.apps import AppConfig


class WorkflowConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.engine.workflows"
    label = "workflow"
    verbose_name = "Workflows"
