from django.apps import AppConfig


class HudsonRockConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.hudson_rock"
    label = "hudson_rock"
    verbose_name = "Infostealer Exposure (Hudson Rock)"
    tool_meta = {
        "label": "Infostealer Exposure (Hudson Rock)",
        "runner": "apps.hudson_rock.scanner.run_hudson_rock",
        "phase": 1,
        "phase_group": "Domain Intelligence",
        "requires": [],
        "produces_findings": True,
        # Passive: queries Hudson Rock's Cavalier API (third-party threat
        # intel), never sends a packet to the target's own systems.
        "active": False,
    }
