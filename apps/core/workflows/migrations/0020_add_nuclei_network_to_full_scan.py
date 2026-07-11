"""Add nuclei_network to the Full Scan workflow.

Full Scan ran only the web nuclei (against httpx URLs) and never the network
nuclei, so nuclei's active protocol/CVE probes were never pointed at the non-web
services naabu/nmap discover (ftp, smtp, imaps, etc.). nmap's version-string
vulners lookup produces nothing on ports where service_detection failed to grab
a banner — exactly where nuclei_network's service-scoped templates add value.
Insert it at order 10 so it sits in the phase-7 (Network Exposure) cluster with
nmap/tls_checker/ssh_checker; execution phase itself comes from tool_meta.
"""

from django.db import migrations
from django.db.models import F


def add_nuclei_network(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Full Scan").first()
    if not wf:
        return
    if WorkflowStep.objects.filter(workflow=wf, tool="nuclei_network").exists():
        return

    # Shift steps at order >= 10 (nuclei, web_checker) down to make room.
    WorkflowStep.objects.filter(workflow=wf, order__gte=10).order_by("-order").update(
        order=F("order") + 1
    )
    WorkflowStep.objects.create(
        workflow=wf, tool="nuclei_network", order=10, enabled=True
    )


def remove_nuclei_network(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Full Scan").first()
    if not wf:
        return

    WorkflowStep.objects.filter(workflow=wf, tool="nuclei_network").delete()
    WorkflowStep.objects.filter(workflow=wf, order__gte=11).order_by("order").update(
        order=F("order") - 1
    )


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0019_fix_delta_category_and_workflowrun_cancelled"),
    ]

    operations = [
        migrations.RunPython(add_nuclei_network, remove_nuclei_network),
    ]
