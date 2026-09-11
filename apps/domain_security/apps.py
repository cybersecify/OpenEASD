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
        "phase_group": "Domain Posture",
        "requires": [],
        "produces_findings": True,
        # PASSIVE: DNS/DNSSEC/CAA/email-auth via public resolvers + RDAP via
        # rdap.org — no packets to the target's own systems. The active probes
        # (AXFR / open-relay / MTA-STS fetch) moved to apps.domain_probe, so this
        # tool can run in a no-auth passive scan.
        "active": False,
    }
