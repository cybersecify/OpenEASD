from django.apps import AppConfig


class AlterxConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.alterx"
    label = "alterx"
    verbose_name = "Alterx"
    tool_meta = {
        "label": "Alterx (Subdomain Permutation)",
        "runner": "apps.alterx.scanner.run_alterx",
        "phase": 3,
        "phase_group": "Asset Discovery",
        "requires": ["subfinder"],
        "produces_findings": False,
        "active": False,
    }
