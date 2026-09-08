"""Create 'Infra Scan' workflow — non-web tools only (no httpx, nuclei web, web_checker)."""

from django.db import migrations


_TOOLS = [
    ("domain_security", 1),
    ("subfinder", 2),
    ("dnsx", 3),
    ("naabu", 4),
    ("nmap", 5),
    ("tls_checker", 6),
    ("ssh_checker", 7),
    ("nuclei_network", 8),
]


def create_infra_scan_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.create(
        name="Infra Scan",
        description="Network/infrastructure scan — non-web tools only. "
                    "Runs domain enumeration, port scanning, service detection, "
                    "TLS/SSH checks, and nuclei network templates.",
        is_default=False,
    )
    for tool, order in _TOOLS:
        WorkflowStep.objects.create(
            workflow=wf, tool=tool, order=order, enabled=True,
        )


def remove_infra_scan_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Infra Scan").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0015_remove_service_detection_from_default"),
    ]

    operations = [
        migrations.RunPython(create_infra_scan_workflow, remove_infra_scan_workflow),
    ]
