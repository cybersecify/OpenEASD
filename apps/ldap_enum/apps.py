"""Tool registration for the LDAP RootDSE metadata reader."""

from django.apps import AppConfig


class LdapEnumConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.ldap_enum"
    label = "ldap_enum"
    verbose_name = "LDAP RootDSE Metadata"
    tool_meta = {
        "label": "LDAP RootDSE Metadata",
        "runner": "apps.ldap_enum.scanner.run_ldap_enum",
        "phase": 7.5,  # after service_detection (7), before nmap (8)
        "phase_group": "Network Exposure",
        "requires": ["naabu", "service_detection"],
        "produces_findings": True,
        "active": True,  # uses Nmap against the target; requires scan authorization
    }
