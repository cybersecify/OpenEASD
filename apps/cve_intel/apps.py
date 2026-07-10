from django.apps import AppConfig


class CveIntelConfig(AppConfig):
    name = "apps.cve_intel"
    label = "cve_intel"
    verbose_name = "CVE Intel (EPSS + KEV)"
    tool_meta = {
        "label": "CVE Intel (EPSS + CISA KEV)",
        "runner": "apps.cve_intel.scanner.run_cve_intel",
        # Phase 12 — after every CVE-producing tool (nmap 7, nuclei_network 7,
        # nuclei 11) so it can enrich all their findings in one pass.
        "phase": 12,
        "phase_group": "Prioritization",
        "requires": [],            # no external binary — pure data enrichment
        "produces_findings": False,  # enriches existing Findings, creates none
    }
