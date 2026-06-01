from django.apps import AppConfig


class AlterxConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.alterx"
    label = "alterx"
    verbose_name = "Alterx"
    tool_meta = {
        "label": "Alterx (Subdomain Permutation)",
        "runner": "apps.alterx.scanner.run_alterx",
        "phase": 2,
        "requires": ["subfinder"],
        "produces_findings": False,
    }
