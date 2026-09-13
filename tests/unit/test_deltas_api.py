"""/api/changes/ — the 'changes since last scan' feed (PR5)."""

import pytest


@pytest.mark.django_db
class TestDeltasAPI:
    def _session(self, domain="example.com"):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(domain=domain, scan_type="full", status="completed")

    def _delta(self, sess, change_type="new", ident="web_checker:missing_header:Missing CSP"):
        from apps.core.engine.scans.models import ScanDelta
        return ScanDelta.objects.create(
            session=sess, change_type=change_type, change_category="finding",
            item_identifier=ident,
        )

    def test_requires_auth(self, client):
        assert client.get("/api/changes/").status_code == 401

    def test_list_shape_and_key_parse(self, auth_client):
        s = self._session()
        self._delta(s, "new", "web_checker:missing_header:Missing CSP header")
        body = auth_client.get("/api/changes/").json()
        assert body["total"] == 1 and "page" in body and "total_pages" in body
        row = body["deltas"][0]
        assert row["change_type"] == "new"
        assert row["source"] == "web_checker" and row["check_type"] == "missing_header"
        assert row["title"] == "Missing CSP header"
        assert row["domain"] == "example.com" and row["scan_uuid"]

    def test_title_with_colon_is_preserved(self, auth_client):
        # split(":", 2) keeps colons in the title intact.
        s = self._session()
        self._delta(s, "new", "nmap:cve:CVE-2024-1: RCE in service X")
        row = auth_client.get("/api/changes/").json()["deltas"][0]
        assert row["source"] == "nmap" and row["check_type"] == "cve"
        assert row["title"] == "CVE-2024-1: RCE in service X"

    def test_filter_change_type(self, auth_client):
        s = self._session()
        self._delta(s, "new", "a:b:c")
        self._delta(s, "removed", "d:e:f")
        assert auth_client.get("/api/changes/?change_type=new").json()["total"] == 1
        assert auth_client.get("/api/changes/?change_type=removed").json()["total"] == 1

    def test_filter_domain(self, auth_client):
        self._delta(self._session("alpha.com"), ident="a:b:c")
        self._delta(self._session("beta.com"), ident="d:e:f")
        assert auth_client.get("/api/changes/?domain=alpha.com").json()["total"] == 1

    def test_route_not_shadowed_by_uuid_detail(self, auth_client):
        # /deltas/ must resolve to the feed, not be parsed as a scan UUID (200, not 404/422).
        assert auth_client.get("/api/changes/").status_code == 200
