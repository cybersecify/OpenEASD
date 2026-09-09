"""Create default 'Full Scan' workflow with all tools enabled."""

from django.db import migrations


_TOOLS = [
    ("domain_security", 1),     # phase 1  — Domain Intelligence
    ("subfinder", 2),            # phase 2  — Surface Enumeration
    ("amass", 3),                # phase 2  — Surface Enumeration
    ("alterx", 4),               # phase 2  — Surface Enumeration
    ("dnsx", 5),                 # phase 3  — Surface Enumeration
    ("takeover_check", 6),       # phase 4  — Surface Enumeration
    ("cloud_assets", 7),         # phase 4  — Surface Enumeration
    ("naabu", 8),                # phase 5  — Port Discovery
    ("nmap", 9),                 # phase 7  — Network Exposure
    ("tls_checker", 10),         # phase 7  — Network Exposure
    ("ssh_checker", 11),         # phase 7  — Network Exposure
    ("nuclei_network", 12),      # phase 7  — Network Exposure
    ("httpx", 13),               # phase 8  — Web Exposure
    ("historical_urls", 14),     # phase 9  — Web Exposure
    ("katana", 15),              # phase 10 — Web Exposure
    ("nuclei", 16),              # phase 11 — Web Exposure
    ("web_checker", 17),         # phase 11 — Web Exposure
    ("cve_intel", 18),           # phase 12 — Prioritization
]


def create_default_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.create(
        name="Full Scan",
        description="Default workflow — runs all tools in pipeline order.",
        is_default=True,
    )
    for tool, order in _TOOLS:
        WorkflowStep.objects.create(
            workflow=wf, tool=tool, order=order, enabled=True,
        )


def remove_default_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Full Scan", is_default=True).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0009_alter_workflowstep_tool_and_more"),
    ]

    operations = [
        migrations.RunPython(create_default_workflow, remove_default_workflow),
    ]
