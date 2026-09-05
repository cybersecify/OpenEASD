from django.apps import AppConfig


class AiConfig(AppConfig):
    """Core AI subsystem — deliberately NOT a registry tool (no tool_meta).

    It runs after scan finalize over the whole session (findings + insights),
    and it has orchestration authority (it may launch subscans). That makes it
    a peer of apps.core.insights, not of the scanner tools — its gate is
    BYOK credentials + recorded consent, never workflow membership.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.ai"
    label = "ai"
    verbose_name = "AI Analysis"
