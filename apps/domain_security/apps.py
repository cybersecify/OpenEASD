from django.apps import AppConfig


class DomainSecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.domain_security"
    label = "domain_security"
    verbose_name = "Domain Security"
    tool_meta = {
        "label": "Domain Security",
        "runner": "apps.domain_security.scanner.run_domain_security",
        "phase": 1,
        "requires": [],
        "produces_findings": True,
    }
