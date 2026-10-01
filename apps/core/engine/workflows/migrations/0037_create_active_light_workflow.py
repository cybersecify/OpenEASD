"""Create the 'Active Light' workflow — the LIGHT active scan mode.

Active Light is the fast *authorized* scan: a discovery backbone feeding a set of
cheap config/exposure checks, deliberately WITHOUT the slow engines (nmap NSE,
nuclei/nuclei_network templates, katana crawl, amass, cloud_assets, takeover,
js_secrets, historical_urls). It is the active counterpart of Quick Recon.

    subfinder     — passive subdomain discovery          ┐ discovery backbone
    dnsx          — resolve to public IPs                 │ (httpx/tls/ssh need
    naabu         — top-100 TCP port scan                 │  ports; naabu also
    httpx         — web probe on discovered host:port     ┘  auto-injects
                                                             service_detection)
    domain_probe  — apex active probes (AXFR/relay/MTA-STS)
    web_checker   — headers / cookies / CORS / security.txt
    tls_checker   — cert / cipher / protocol on all ports
    ssh_checker   — SSH config on ssh ports

service_detection is NOT listed — it is core:True (hidden) and the runner
auto-injects it after naabu, so it runs without being a stored step.

Active Light contains active tools, so is_passive_tool_set() is False and the
scan-start gate requires DomainAuthorization (apps/core/engine/scans/api.py) —
no new auth code. Membership MUST stay in sync with
tests/unit/test_active_light.py (exact set + heavy-engine exclusion), so a drift
fails CI. Not the default workflow — Full Scan (active deep) remains the default.
"""

from django.db import migrations

# Light active tools in pipeline-phase order. Order is cosmetic (the runner
# regroups by registry phase); it mirrors the pipeline for a readable UI.
_TOOLS = [
    ("subfinder", 1),
    ("dnsx", 2),
    ("naabu", 3),
    ("httpx", 4),
    ("domain_probe", 5),
    ("web_checker", 6),
    ("tls_checker", 7),
    ("ssh_checker", 8),
]


def create_active_light_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    if Workflow.objects.filter(name="Active Light").exists():
        return  # idempotent

    wf = Workflow.objects.create(
        name="Active Light",
        description="Fast authorized scan — subdomain/port discovery plus quick "
                    "config/exposure checks (web headers, TLS, SSH, domain probes). "
                    "Skips the slow engines (nuclei/nmap NSE/crawl/amass). Probes "
                    "the target directly, so it requires domain authorization.",
        is_default=False,
    )
    for tool, order in _TOOLS:
        WorkflowStep.objects.create(workflow=wf, tool=tool, order=order, enabled=True)


def remove_active_light_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Active Light").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0036_create_quick_recon_workflow"),
    ]

    operations = [
        migrations.RunPython(create_active_light_workflow, remove_active_light_workflow),
    ]
