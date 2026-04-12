"""Create default 'Full Scan' workflow with all tools enabled."""

from django.db import migrations


_TOOLS = [
    ("domain_security", 1),
    ("subfinder", 2),
    ("dnsx", 3),
    ("naabu", 4),
    ("httpx", 5),
    ("nmap", 6),
    ("tls_checker", 7),
    ("ssh_checker", 8),
    ("nuclei", 9),
    ("web_checker", 10),
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
