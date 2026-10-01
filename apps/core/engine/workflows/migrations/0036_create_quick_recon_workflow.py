"""Create the 'Quick Recon' workflow — the LIGHT passive tier.

Quick Recon is the instant, no-auth first look: four apex-scoped passive tools
that each hit the apex (or a third-party API keyed on it) with a handful of
lookups and finish in seconds — no subdomain/CT/archive enumeration, no
discovery fan-out, nothing downstream depending on them:

    domain_security  — DNS/DNSSEC/CAA/email-auth + RDAP via public resolvers
    dns_history      — one passive-DNS API call
    hudson_rock      — one keyless infostealer-exposure API call
    breach_check     — one keyless/BYOK data-breach API call

All four are passive (active=False), so Quick Recon needs NO DomainAuthorization
for a `now` scan (see apps/core/engine/scans/api.py). The membership here MUST
stay in sync with registry.light_passive_tools() (passive AND quick_recon);
tests/unit/test_quick_recon.py::TestQuickReconWorkflow binds the two in both
directions, so a flag/workflow drift fails CI.

Not the default workflow — Full Scan (active, gated) remains the default.
"""

from django.db import migrations

# Light passive tools in pipeline-phase order. Order is cosmetic (the runner
# regroups by registry phase); it mirrors the pipeline for a readable UI.
_TOOLS = [
    ("domain_security", 1),
    ("dns_history", 2),
    ("hudson_rock", 3),
    ("breach_check", 4),
]


def create_quick_recon_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    if Workflow.objects.filter(name="Quick Recon").exists():
        return  # idempotent

    wf = Workflow.objects.create(
        name="Quick Recon",
        description="Instant passive snapshot — four apex-scoped, keyless-capable "
                    "tools (domain posture, historical DNS, infostealer and "
                    "data-breach exposure). Public/third-party data only, no "
                    "packets to the target, finishes in seconds. Requires no "
                    "domain authorization.",
        is_default=False,
    )
    for tool, order in _TOOLS:
        WorkflowStep.objects.create(workflow=wf, tool=tool, order=order, enabled=True)


def remove_quick_recon_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Quick Recon").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0035_supersede_typosquat_with_tldsquatting"),
    ]

    operations = [
        migrations.RunPython(create_quick_recon_workflow, remove_quick_recon_workflow),
    ]
