from django.apps import AppConfig


class DnsHistoryConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.dns_history"
    label = "dns_history"
    verbose_name = "Historical DNS Records"
    tool_meta = {
        "label": "Historical DNS Records",
        "runner": "apps.dns_history.scanner.run_dns_history",
        "phase": 1,
        "phase_group": "Domain Posture",
        "requires": [],
        "produces_findings": True,
        # Passive: queries a third-party passive-DNS dataset, never the target's
        # own systems. No packets to the target → no DomainAuthorization needed.
        "active": False,
    }
