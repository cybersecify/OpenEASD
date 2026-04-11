from django.db import migrations


def copy_findings(apps, schema_editor):
    Finding = apps.get_model("findings", "Finding")
    DomainFinding = apps.get_model("domain_security", "DomainFinding")
    NmapFinding = apps.get_model("nmap", "NmapFinding")

    new_findings = []

    for d in DomainFinding.objects.all():
        new_findings.append(Finding(
            session_id=d.session_id,
            source="domain_security",
            check_type=d.check_type,
            severity=d.severity,
            title=d.title,
            description=d.description or "",
            remediation=d.remediation or "",
            target=d.domain or "",
            extra=d.extra or {},
            discovered_at=d.discovered_at,
        ))

    for n in NmapFinding.objects.all():
        new_findings.append(Finding(
            session_id=n.session_id,
            port_id=n.port_id,
            source="nmap",
            check_type="cve",
            severity=n.severity,
            title=n.title,
            description=n.description or "",
            remediation="",
            target=f"{n.address}:{n.port_number}" if n.address else "",
            extra={
                "cve": n.cve,
                "cvss_score": n.cvss_score,
                "service": n.service,
                "version": n.version,
                "nse_script": n.nse_script,
                "port_number": n.port_number,
                "address": n.address,
            },
            discovered_at=n.discovered_at,
        ))

    if new_findings:
        Finding.objects.bulk_create(new_findings, ignore_conflicts=True)


def reverse_noop(apps, schema_editor):
    Finding = apps.get_model("findings", "Finding")
    Finding.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ("findings", "0001_initial"),
        ("domain_security", "0002_remove_ssl_check_type"),
        ("nmap", "0002_nmapfinding_delete_serviceresult_and_more"),
    ]

    operations = [
        migrations.RunPython(copy_findings, reverse_noop),
    ]
