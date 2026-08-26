from django.apps import AppConfig


class JsSecretsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.js_secrets"
    label = "js_secrets"
    verbose_name = "JS Secrets (gitleaks)"
    tool_meta = {
        "label": "JS Secrets (gitleaks)",
        "runner": "apps.js_secrets.scanner.run_js_secrets",
        "phase": 11,
        "phase_group": "Web Exposure",
        "requires": ["gitleaks"],
        "produces_findings": True,
        "active": True,  # fetches JS from the target — active
    }
