"""Make 'Full Scan' the default workflow and bring it up to the full tool set.

Context: 0017 had set 'Infra Scan' (non-web only) as the default. Product
decision is to default to the complete Full Scan again. Existing databases
still carry the older Full Scan (created by 0010 before its tool list was
expanded, + nuclei_network from 0020), so this migration also fills in any
canonical tools Full Scan is missing.

Additive and idempotent: only tools not already present are appended (enabled),
so a user who customised Full Scan keeps their toggles. Execution order is
unaffected — the runner groups tools by registry phase, so appended steps still
run in the correct phase regardless of their `order` value. service_detection is
omitted deliberately: it is a core tool auto-injected by the runner (see 0015).
"""

from django.db import migrations

# Canonical Full Scan tool set (18 non-core tools, in pipeline phase order).
_FULL_SCAN_TOOLS = [
    "domain_security", "subfinder", "amass", "alterx", "dnsx",
    "takeover_check", "cloud_assets", "naabu", "nmap", "tls_checker",
    "ssh_checker", "nuclei_network", "httpx", "historical_urls", "katana",
    "nuclei", "web_checker", "cve_intel",
]


def set_full_scan_default(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    wf = Workflow.objects.filter(name="Full Scan").first()
    if wf is None:
        return  # defensive: nothing to promote

    # Fill in any missing canonical tools, appended after the current max order.
    existing = set(wf.steps.values_list("tool", flat=True))
    next_order = (wf.steps.order_by("-order").values_list("order", flat=True).first() or 0) + 1
    for tool in _FULL_SCAN_TOOLS:
        if tool not in existing:
            WorkflowStep.objects.create(workflow=wf, tool=tool, order=next_order, enabled=True)
            next_order += 1

    # Exactly one default.
    Workflow.objects.exclude(pk=wf.pk).update(is_default=False)
    Workflow.objects.filter(pk=wf.pk).update(is_default=True)


def restore_infra_scan_default(apps, schema_editor):
    # Reverse only flips the default back to Infra Scan; appended steps are
    # harmless while Full Scan is not the default and are left in place.
    Workflow = apps.get_model("workflow", "Workflow")
    infra = Workflow.objects.filter(name="Infra Scan").first()
    if infra is None:
        return
    Workflow.objects.exclude(pk=infra.pk).update(is_default=False)
    Workflow.objects.filter(pk=infra.pk).update(is_default=True)


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0020_add_nuclei_network_to_full_scan"),
    ]

    operations = [
        migrations.RunPython(set_full_scan_default, restore_infra_scan_default),
    ]
