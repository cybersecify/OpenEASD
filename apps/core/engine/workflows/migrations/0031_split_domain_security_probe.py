"""Wire up the domain_security -> {domain_security (passive), domain_probe (active)} split.

``domain_security`` is now PASSIVE (DNS/email-auth via public resolvers + RDAP);
its active probes (AXFR zone transfer, SMTP open-relay, MTA-STS policy fetch)
moved to the new ``domain_probe`` tool. This migration adjusts the two default
workflows to match:

  * domain_probe  -> Full Scan    — the invariant
    test_full_scan_covers_every_registered_tool requires every non-core registered
    tool to be in the default Full Scan. domain_probe is active, so it joins ONLY
    Full Scan (never the passive, no-auth Passive Scan).
  * domain_security -> Passive Scan — now that it's passive it belongs in the
    no-auth passive recon workflow, so a passive scan finally includes the
    DNS/DNSSEC/SPF/DMARC/DKIM/RDAP intelligence. (It is already in Full Scan.)

Additive and idempotent (skips if already present), matching 0023/0029/0030.
Execution order is unaffected — the runner regroups steps by registry phase.
"""

from django.db import migrations

# (tool, workflow) pairs to ensure-present
_ADDITIONS = [
    ("domain_probe", "Full Scan"),
    ("domain_security", "Passive Scan"),
]


def _add_step(wf, tool, WorkflowStep):
    if wf.steps.filter(tool=tool).exists():
        return
    next_order = (
        wf.steps.order_by("-order").values_list("order", flat=True).first() or 0
    ) + 1
    WorkflowStep.objects.create(workflow=wf, tool=tool, order=next_order, enabled=True)


def apply_split(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    for tool, wf_name in _ADDITIONS:
        wf = Workflow.objects.filter(name=wf_name).first()
        if wf is None:
            continue
        _add_step(wf, tool, WorkflowStep)


def unapply_split(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")
    # Only remove what this migration added: domain_probe from Full Scan and
    # domain_security from Passive Scan (leave domain_security in Full Scan).
    for tool, wf_name in _ADDITIONS:
        wf = Workflow.objects.filter(name=wf_name).first()
        if wf is None:
            continue
        WorkflowStep.objects.filter(workflow=wf, tool=tool).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0030_add_dns_history_to_workflows"),
    ]

    operations = [
        migrations.RunPython(apply_split, unapply_split),
    ]
