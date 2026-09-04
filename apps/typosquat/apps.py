from django.apps import AppConfig


class TyposquatConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.typosquat"
    label = "typosquat"
    verbose_name = "Lookalike / Typosquat Domains"
    tool_meta = {
        "label": "Lookalike / Typosquat Domains",
        "runner": "apps.typosquat.scanner.run_typosquat",
        "phase": 1,
        "phase_group": "Domain Intelligence",
        "requires": [],
        "produces_findings": True,
        # Passive: generates lookalike candidates algorithmically from the apex
        # domain, then queries the CANDIDATE domains' PUBLIC DNS (A/MX/NS) to see
        # which are registered / weaponizable. Sends ZERO packets to the target's
        # own systems — the target is never contacted. No DomainAuthorization,
        # no API key needed.
        "active": False,
    }
