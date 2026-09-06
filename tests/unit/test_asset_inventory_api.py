"""Tests for the /api/assets/ endpoints (asset inventory PR2)."""

import pytest
from django.contrib.auth.models import User
from django.utils import timezone
from ninja_jwt.tokens import AccessToken

pytestmark = pytest.mark.django_db


@pytest.fixture
def auth_client(client):
    user = User.objects.create_user(username="assettest", password="pass123")
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {AccessToken.for_user(user)}"
    return client


def _domain(name="example.com"):
    from apps.core.domains.models import Domain
    return Domain.objects.get_or_create(name=name)[0]


def _asset(domain, kind, key, status="active", **extra):
    from apps.core.asset_inventory.models import Asset
    now = timezone.now()
    return Asset.objects.create(
        domain=domain, kind=kind, key=key, status=status,
        first_seen=now, last_seen=now, extra=extra,
    )


def _session(domain="example.com", status="completed"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, scan_type="full", status=status)


def _finding(session, asset, severity="high"):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, asset=asset, source="nmap", check_type="cve",
        severity=severity, title="t", status="open",
    )


class TestAuth:
    def test_list_requires_auth(self, client):
        assert client.get("/api/assets/").status_code == 401

    def test_detail_requires_auth(self, client):
        assert client.get("/api/assets/1/").status_code == 401


class TestList:
    def test_returns_assets_with_pagination_shape(self, auth_client):
        d = _domain()
        _asset(d, "subdomain", "a.example.com")
        _asset(d, "ip", "1.2.3.4")
        body = auth_client.get("/api/assets/").json()
        assert body["total"] == 2
        assert {a["key"] for a in body["assets"]} == {"a.example.com", "1.2.3.4"}
        assert body["page"] == 1 and "total_pages" in body and "has_next" in body

    def test_filter_by_kind(self, auth_client):
        d = _domain()
        _asset(d, "subdomain", "a.example.com")
        _asset(d, "ip", "1.2.3.4")
        body = auth_client.get("/api/assets/?kind=ip").json()
        assert [a["kind"] for a in body["assets"]] == ["ip"]

    def test_filter_by_status(self, auth_client):
        d = _domain()
        _asset(d, "subdomain", "live.example.com", status="active")
        _asset(d, "subdomain", "old.example.com", status="gone")
        body = auth_client.get("/api/assets/?status=gone").json()
        assert [a["key"] for a in body["assets"]] == ["old.example.com"]

    def test_search_by_key(self, auth_client):
        d = _domain()
        _asset(d, "subdomain", "api.example.com")
        _asset(d, "subdomain", "www.example.com")
        body = auth_client.get("/api/assets/?q=api").json()
        assert [a["key"] for a in body["assets"]] == ["api.example.com"]

    def test_per_asset_open_finding_counts(self, auth_client):
        d = _domain()
        a = _asset(d, "port", "1.2.3.4:443/tcp")
        s = _session()
        _finding(s, a, "critical")
        _finding(s, a, "high")
        _finding(s, a, "high")
        row = auth_client.get("/api/assets/").json()["assets"][0]
        assert row["findings"]["critical"] == 1
        assert row["findings"]["high"] == 2
        assert row["findings"]["low"] == 0


class TestSummary:
    def test_summary_totals_and_by_kind(self, auth_client):
        d = _domain()
        _asset(d, "subdomain", "a.example.com", status="active")
        _asset(d, "subdomain", "b.example.com", status="gone")
        _asset(d, "ip", "1.2.3.4", status="active")
        body = auth_client.get("/api/assets/summary/").json()
        assert body["total"] == 3
        assert body["active"] == 2 and body["gone"] == 1
        assert body["by_kind"]["subdomain"] == {"active": 1, "gone": 1}
        assert body["by_kind"]["ip"]["active"] == 1


class TestDetail:
    def test_detail_shape_and_findings(self, auth_client):
        d = _domain()
        a = _asset(d, "port", "1.2.3.4:22/tcp", service="ssh")
        s = _session()
        _finding(s, a, "high")
        body = auth_client.get(f"/api/assets/{a.id}/").json()
        assert body["key"] == "1.2.3.4:22/tcp"
        assert body["extra"]["service"] == "ssh"
        assert len(body["findings"]) == 1 and body["findings"][0]["severity"] == "high"

    def test_detail_seen_in_scans(self, auth_client):
        d = _domain()
        a = _asset(d, "subdomain", "a.example.com")
        s = _session()
        from apps.core.assets.models import Subdomain
        Subdomain.objects.create(
            session=s, domain="example.com", subdomain="a.example.com", source="subfinder"
        )
        body = auth_client.get(f"/api/assets/{a.id}/").json()
        assert [t["uuid"] for t in body["seen_in_scans"]] == [str(s.uuid)]

    def test_detail_404(self, auth_client):
        assert auth_client.get("/api/assets/99999/").status_code == 404
