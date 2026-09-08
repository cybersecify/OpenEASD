"""Create the 'Passive Scan' workflow — passive tools only (no target contact).

A passive scan gathers attack-surface data from public / third-party sources
only: certificate transparency and other subdomain feeds (subfinder), owned
ASN/CIDR registries (asn_discovery), subdomain permutation candidates (alterx),
DNS resolution via public resolvers (dnsx), cloud-provider bucket enumeration
(cloud_assets), web-archive URLs (historical_urls), and CVE threat-intel feeds
(cve_intel). None of these send packets to the target's own systems, so a
Passive Scan requires NO DomainAuthorization (see apps/core/scans/api.py).

The tool list here MUST stay in sync with the passive classification in each
tool's AppConfig.tool_meta (`active=False`). tests/unit/test_passive_scan.py
asserts every step of this workflow is passive, so a future edit that adds an
active tool here fails CI rather than silently probing an unauthorized target.

Not the default workflow — Full Scan (active, gated) remains the default.
"""

from django.db import migrations

# Passive tools in pipeline phase order. Order is cosmetic (the runner regroups
# by registry phase); it mirrors the pipeline for a readable UI.
_TOOLS = [
    ("subfinder", 1),
    ("asn_discovery", 2),
    ("alterx", 3),
    ("dnsx", 4),
    ("cloud_assets", 5),
    ("historical_urls", 6),
    ("cve_intel", 7),
]


def create_passive_scan_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    if Workflow.objects.filter(name="Passive Scan").exists():
        return  # idempotent

    wf = Workflow.objects.create(
        name="Passive Scan",
        description="Passive-only recon — public and third-party data sources "
                    "only, no packets to the target. Discovers subdomains, owned "
                    "IP ranges, resolved IPs, exposed cloud buckets, and archived "
                    "URLs. Requires no domain authorization.",
        is_default=False,
    )
    for tool, order in _TOOLS:
        WorkflowStep.objects.create(workflow=wf, tool=tool, order=order, enabled=True)


def remove_passive_scan_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Passive Scan").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0021_set_full_scan_default_and_complete"),
    ]

    operations = [
        migrations.RunPython(create_passive_scan_workflow, remove_passive_scan_workflow),
    ]
