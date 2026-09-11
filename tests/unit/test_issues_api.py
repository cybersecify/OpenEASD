"""/api/issues/ — the persistent finding register API (PR3)."""

import pytest
from django.utils import timezone


def _issue(domain, **kw):
    from apps.core.data.findings.models import Issue, issue_key
    now = timezone.now()
    defaults = dict(
        source="web_checker", check_type="missing_header", title="Missing CSP",
        target="example.com", severity="medium", status="open",
        first_seen=now, last_seen=now,
    )
    defaults.update(kw)
    defaults["key"] = issue_key(defaults["source"], defaults["check_type"],
                                defaults["title"], defaults["target"])
    return Issue.objects.create(domain=domain, **defaults)


@pytest.mark.django_db
class TestIssuesAPI:
    def _domain(self, name="example.com"):
        from apps.core.data.domains.models import Domain
        d, _ = Domain.objects.get_or_create(name=name)
        return d

    def test_requires_auth(self, client):
        assert client.get("/api/issues/").status_code == 401

    def test_list_ranked_and_shaped(self, auth_client):
        dom = self._domain()
        _issue(dom, title="low one", severity="low")
        _issue(dom, title="crit one", severity="critical", check_type="rce")
        res = auth_client.get("/api/issues/?status=")  # all statuses
        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 2 and "page" in body and "total_pages" in body
        # Ranked most-severe first.
        assert body["issues"][0]["severity"] == "critical"
        assert {"id", "title", "severity", "status", "domain", "last_seen"} <= set(body["issues"][0])

    def test_filter_by_status_and_severity(self, auth_client):
        dom = self._domain()
        _issue(dom, title="open med", severity="medium", status="open")
        _issue(dom, title="fp high", severity="high", status="false_positive", check_type="x")
        assert auth_client.get("/api/issues/?status=open").json()["total"] == 1
        assert auth_client.get("/api/issues/?severity=high").json()["total"] == 1
        assert auth_client.get("/api/issues/?status=false_positive").json()["issues"][0]["title"] == "fp high"

    def test_summary(self, auth_client):
        dom = self._domain()
        _issue(dom, title="a", severity="high", status="open")
        _issue(dom, title="b", severity="high", status="open", check_type="y")
        _issue(dom, title="c", severity="low", status="false_positive", check_type="z")
        s = auth_client.get("/api/issues/summary/").json()
        assert s["total"] == 3
        assert s["by_status"]["open"] == 2 and s["by_status"]["false_positive"] == 1
        # open_by_severity counts only actionable issues.
        assert s["open_by_severity"].get("high") == 2
        assert "low" not in s["open_by_severity"]  # the low one is dismissed

    def test_status_update_persists(self, auth_client):
        dom = self._domain()
        i = _issue(dom, status="open")
        res = auth_client.post(f"/api/issues/{i.id}/status/",
                               data={"status": "false_positive"},
                               content_type="application/json")
        assert res.status_code == 200
        assert res.json()["status"] == "false_positive"
        i.refresh_from_db()
        assert i.status == "false_positive"

    def test_status_update_rejects_bad_value(self, auth_client):
        dom = self._domain()
        i = _issue(dom)
        res = auth_client.post(f"/api/issues/{i.id}/status/",
                               data={"status": "bogus"},
                               content_type="application/json")
        assert res.status_code == 400

    def test_status_update_404(self, auth_client):
        res = auth_client.post("/api/issues/999999/status/",
                               data={"status": "open"},
                               content_type="application/json")
        assert res.status_code == 404
