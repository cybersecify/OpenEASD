"""Tests for the persistent asset inventory rollup (PR1).

Spec: docs/specs/2026-09-06-asset-centric-inventory.md
"""

import pytest

from apps.core.asset_inventory.models import Asset
from apps.core.asset_inventory.rollup import rollup_session

pytestmark = pytest.mark.django_db


def _domain(name="example.com"):
    from apps.core.domains.models import Domain
    return Domain.objects.get_or_create(name=name)[0]


def _session(domain="example.com", status="completed", scan_type="full"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, status=status, scan_type=scan_type)


def _sub(session, name, source="subfinder"):
    from apps.core.assets.models import Subdomain
    return Subdomain.objects.create(
        session=session, domain=session.domain, subdomain=name, source=source
    )


def _ip(session, addr, version=4, source="dnsx"):
    from apps.core.assets.models import IPAddress
    return IPAddress.objects.create(
        session=session, address=addr, version=version, source=source
    )


def _port(session, addr, port, proto="tcp", service="", is_web=False, source="naabu"):
    from apps.core.assets.models import Port
    return Port.objects.create(
        session=session, address=addr, port=port, protocol=proto,
        service=service, is_web=is_web, source=source,
    )


def _url(session, url, source="httpx", **kw):
    from apps.core.web_assets.models import URL
    return URL.objects.create(session=session, url=url, source=source, **kw)


def _finding(session, **kw):
    from apps.core.findings.models import Finding
    defaults = dict(source="nmap", check_type="cve", severity="high", title="t")
    defaults.update(kw)
    return Finding.objects.create(session=session, **defaults)


class TestRollup:
    def test_creates_one_asset_per_kind(self):
        _domain()
        s = _session()
        _sub(s, "api.example.com")
        _ip(s, "1.2.3.4")
        _port(s, "1.2.3.4", 443, service="https", is_web=True)
        _url(s, "https://api.example.com/")
        rollup_session(s)

        kinds = dict(Asset.objects.values_list("kind", "key"))
        assert kinds == {
            "subdomain": "api.example.com",
            "ip": "1.2.3.4",
            "port": "1.2.3.4:443/tcp",
            "url": "https://api.example.com/",
        }
        assert set(Asset.objects.values_list("status", flat=True)) == {"active"}
        port = Asset.objects.get(kind="port")
        assert port.extra["service"] == "https" and port.extra["is_web"] is True

    def test_no_domain_row_skips(self):
        s = _session(domain="unknown.com")  # no Domain row created
        _sub(s, "a.unknown.com")
        rollup_session(s)
        assert Asset.objects.count() == 0

    def test_subscan_skipped(self):
        _domain()
        s = _session(scan_type="subscan")
        _sub(s, "a.example.com")
        rollup_session(s)
        assert Asset.objects.count() == 0

    def test_dedup_across_scans(self):
        d = _domain()
        s1 = _session()
        _sub(s1, "a.example.com")
        rollup_session(s1)
        first = Asset.objects.get(kind="subdomain", key="a.example.com")

        s2 = _session()
        _sub(s2, "a.example.com")
        rollup_session(s2)

        assert Asset.objects.filter(domain=d, kind="subdomain").count() == 1
        again = Asset.objects.get(kind="subdomain", key="a.example.com")
        assert again.id == first.id
        assert again.last_scan_id == s2.id
        assert again.status == "active"
        assert again.first_seen <= again.last_seen

    def test_gone_marking_on_completed_scan(self):
        _domain()
        s1 = _session()
        _sub(s1, "a.example.com")
        _sub(s1, "b.example.com")
        rollup_session(s1)

        s2 = _session()  # completed; only 'a' seen this time
        _sub(s2, "a.example.com")
        rollup_session(s2)

        assert Asset.objects.get(key="a.example.com").status == "active"
        assert Asset.objects.get(key="b.example.com").status == "gone"

    def test_gone_marking_only_for_observed_kinds(self):
        _domain()
        s1 = _session()
        _sub(s1, "a.example.com")
        _ip(s1, "9.9.9.9")
        rollup_session(s1)

        s2 = _session()  # sees the subdomain but produced NO ips this scan
        _sub(s2, "a.example.com")
        rollup_session(s2)

        # ip kind wasn't observed in s2 → its asset must NOT be gone-marked
        assert Asset.objects.get(kind="ip", key="9.9.9.9").status == "active"

    def test_partial_scan_does_not_gone_mark(self):
        _domain()
        s1 = _session()
        _sub(s1, "a.example.com")
        _sub(s1, "b.example.com")
        rollup_session(s1)

        s2 = _session(status="partial")  # only 'a', but partial
        _sub(s2, "a.example.com")
        rollup_session(s2)

        assert Asset.objects.get(key="b.example.com").status == "active"  # not reaped


class TestFindingLink:
    def test_linked_to_url_asset(self):
        _domain()
        s = _session()
        u = _url(s, "https://api.example.com/x")
        f = _finding(s, url=u, source="nuclei", target="api.example.com")
        rollup_session(s)
        f.refresh_from_db()
        assert f.asset is not None and f.asset.kind == "url"

    def test_linked_to_port_asset(self):
        _domain()
        s = _session()
        p = _port(s, "1.2.3.4", 22, service="ssh")
        f = _finding(s, port=p, source="ssh_checker", target="1.2.3.4:22")
        rollup_session(s)
        f.refresh_from_db()
        assert f.asset is not None and f.asset.kind == "port" and f.asset.key == "1.2.3.4:22/tcp"

    def test_linked_by_target_subdomain(self):
        _domain()
        s = _session()
        _sub(s, "a.example.com")
        f = _finding(s, source="domain_security", target="a.example.com")
        rollup_session(s)
        f.refresh_from_db()
        assert f.asset is not None and f.asset.kind == "subdomain"

    def test_unresolvable_target_leaves_null(self):
        _domain()
        s = _session()
        _sub(s, "a.example.com")
        f = _finding(s, source="domain_security", target="nomatch.example.com")
        rollup_session(s)
        f.refresh_from_db()
        assert f.asset is None
