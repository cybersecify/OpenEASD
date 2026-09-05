from django.apps import AppConfig


class BreachCheckConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.breach_check"
    label = "breach_check"
    verbose_name = "Breach Exposure (HIBP / XposedOrNot)"
    tool_meta = {
        "label": "Breach Exposure (HIBP / XposedOrNot)",
        "runner": "apps.breach_check.scanner.run_breach_check",
        "phase": 1,
        "phase_group": "Domain Intelligence",
        "requires": [],
        "produces_findings": True,
        # Passive: queries third-party breach datasets (XposedOrNot's public
        # catalog, or Have I Been Pwned when a key is set). Sends ZERO packets to
        # the target's own systems — no DomainAuthorization needed. BYOK is
        # optional: with no key it uses the free keyless XposedOrNot tier, so the
        # tool always adds value out of the box.
        "active": False,
    }
