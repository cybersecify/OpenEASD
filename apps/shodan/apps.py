from django.apps import AppConfig


class ShodanConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.shodan"
    label = "shodan"
    verbose_name = "Shodan Exposure Intelligence"
    tool_meta = {
        "label": "Shodan Exposure (passive)",
        "runner": "apps.shodan.scanner.run_shodan",
        "phase": 5,
        "phase_group": "Port Discovery",
        "requires": [],
        "produces_findings": True,
        # Passive: reads Shodan's own internet-wide scan dataset (InternetDB, or
        # the host API when a key is set). Sends ZERO packets to the target's own
        # systems — no DomainAuthorization needed. BYOK is optional: no key falls
        # back to the free InternetDB endpoint, so the tool always adds value.
        "active": False,
    }
