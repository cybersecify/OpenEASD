from django.apps import AppConfig


class DomainProbeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.domain_probe"
    label = "domain_probe"
    verbose_name = "Domain Probes"
    tool_meta = {
        "label": "Domain Probes",
        "runner": "apps.domain_probe.scanner.run_domain_probe",
        "phase": 1,
        "phase_group": "Domain Intelligence",
        "requires": [],
        "produces_findings": True,
        # ACTIVE: these checks touch the target directly — AXFR zone transfers
        # against its nameservers, an SMTP relay probe against its MX, and a fetch
        # of its MTA-STS policy file. Split out of domain_security so the passive
        # DNS/email/RDAP intelligence can run in a no-auth passive scan.
        "active": True,
    }
