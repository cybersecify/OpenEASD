"""Enable the read-only LDAP metadata tool in the authorized Full Scan only."""

from django.db import migrations


def add_ldap_enum(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    workflow = Workflow.objects.filter(name="Full Scan").first()
    if workflow is None:
        return
    next_order = (workflow.steps.order_by("-order").values_list("order", flat=True).first() or 0) + 1
    WorkflowStep.objects.get_or_create(
        workflow=workflow, tool="ldap_enum", defaults={"order": next_order, "enabled": True},
    )


def remove_ldap_enum(apps, schema_editor):
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    WorkflowStep.objects.filter(workflow__name="Full Scan", tool="ldap_enum").delete()


class Migration(migrations.Migration):
    dependencies = [("workflow", "0039_rename_passive_scan_to_passive_scan_deep")]
    operations = [migrations.RunPython(add_ldap_enum, remove_ldap_enum)]
