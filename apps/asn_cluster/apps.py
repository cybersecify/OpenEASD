from django.apps import AppConfig


class AsnClusterConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.asn_cluster"
    label = "asn_cluster"
    verbose_name = "Lookalike ASN Clustering"
    tool_meta = {
        "label": "Lookalike ASN Clustering",
        "runner": "apps.asn_cluster.scanner.run_asn_cluster",
        # Late phase: it correlates typosquat's already-written lookalike findings,
        # so it must run after phase 1. Sits with cve_intel in Prioritization order.
        "phase": 13,
        "phase_group": "Domain Intelligence",
        "requires": ["typosquat"],
        "produces_findings": True,
        # PASSIVE: IP→ASN via Team Cymru's keyless DNS service (a third party) —
        # never contacts the target or the lookalike domains. No auth needed.
        "active": False,
    }
