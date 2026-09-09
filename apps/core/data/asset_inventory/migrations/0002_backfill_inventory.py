"""Backfill the persistent asset inventory from existing session-scoped assets.

One-time rollup of history: for each Domain, dedupe every Subdomain / IPAddress /
Port / URL across its (non-subscan) scans into `Asset` rows, with first_seen =
earliest observation and last_seen = latest. Status is set to `active`; the next
live scan's rollup reconciles `gone`-marking (computing it accurately in a
backfill is not worth the complexity). Idempotent via ignore_conflicts.
"""

from django.db import migrations


def backfill(apps, schema_editor):
    Domain = apps.get_model("domains", "Domain")
    ScanSession = apps.get_model("scans", "ScanSession")
    Subdomain = apps.get_model("assets", "Subdomain")
    IPAddress = apps.get_model("assets", "IPAddress")
    Port = apps.get_model("assets", "Port")
    URL = apps.get_model("web_assets", "URL")
    Asset = apps.get_model("asset_inventory", "Asset")

    for domain in Domain.objects.all():
        session_ids = list(
            ScanSession.objects.filter(domain=domain.name)
            .exclude(scan_type="subscan")
            .values_list("id", flat=True)
        )
        if not session_ids:
            continue

        acc: dict[tuple[str, str], list] = {}

        def note(kind, key, ts, extra):
            if not key:
                return
            cur = acc.get((kind, key))
            if cur is None:
                acc[(kind, key)] = [ts, ts, dict(extra)]
            else:
                if ts < cur[0]:
                    cur[0] = ts
                if ts > cur[1]:
                    cur[1] = ts
                cur[2].update(extra)

        for s in Subdomain.objects.filter(session_id__in=session_ids):
            note("subdomain", s.subdomain, s.discovered_at, {"source": s.source})
        for ip in IPAddress.objects.filter(session_id__in=session_ids):
            note("ip", ip.address, ip.discovered_at, {"version": ip.version})
        for p in Port.objects.filter(session_id__in=session_ids):
            note("port", f"{p.address}:{p.port}/{p.protocol}", p.discovered_at,
                 {"service": p.service, "is_web": p.is_web})
        for u in URL.objects.filter(session_id__in=session_ids):
            note("url", u.url, u.discovered_at, {"status_code": u.status_code})

        Asset.objects.bulk_create(
            [
                Asset(domain=domain, kind=kind, key=key,
                      first_seen=first, last_seen=last, status="active", extra=extra)
                for (kind, key), (first, last, extra) in acc.items()
            ],
            ignore_conflicts=True,
        )


def unbackfill(apps, schema_editor):
    # The inventory is fully derived — safe to clear on reverse.
    apps.get_model("asset_inventory", "Asset").objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ("asset_inventory", "0001_initial"),
        ("domains", "0005_domainauthorization"),
        ("scans", "0014_scansession_uniq_active_scan_per_domain"),
        ("assets", "0008_remove_url"),
        ("web_assets", "0003_url_technologies"),
    ]

    operations = [
        migrations.RunPython(backfill, unbackfill),
    ]
