"""Unit tests for apps/core/ai/api.py — config/consent, connection test,
audit log endpoints."""

import json

import pytest
from unittest.mock import patch

from apps.core.ai.models import AIInvocation, AISettings


def _post(client, path, body):
    return client.post(path, data=json.dumps(body), content_type="application/json")


@pytest.fixture
def configured(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct"
    settings.CLOUDFLARE_API_TOKEN = "tok"
    return settings


@pytest.fixture
def unconfigured(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = ""
    settings.CLOUDFLARE_API_TOKEN = ""
    return settings


@pytest.mark.django_db
class TestConfigEndpoint:
    def test_requires_auth(self, client):
        assert client.get("/api/ai/config/").status_code == 401

    def test_get_shape_never_leaks_values(self, auth_client, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = "SECRET-ACCT-8fd2"
        settings.CLOUDFLARE_API_TOKEN = "SECRET-TOKEN-9ab1"
        resp = auth_client.get("/api/ai/config/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is True
        assert data["account_id_set"] is True
        assert data["api_token_set"] is True
        assert data["enabled"] is False
        assert data["consent_current"] is False
        # Presence booleans only — the values must never appear anywhere.
        body = resp.content.decode()
        assert "SECRET-ACCT-8fd2" not in body
        assert "SECRET-TOKEN-9ab1" not in body

    def test_enable_without_env_400(self, auth_client, unconfigured):
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True, "consent_accepted": True})
        assert resp.status_code == 400
        assert AISettings.get().enabled is False

    def test_enable_without_consent_400(self, auth_client, configured):
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True})
        assert resp.status_code == 400
        assert "CONSENT_REQUIRED" in resp.content.decode()
        assert AISettings.get().enabled is False

    def test_enable_with_consent_stamps_fields(self, auth_client, configured):
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True, "consent_accepted": True})
        assert resp.status_code == 200
        cfg = AISettings.get()
        assert cfg.enabled is True
        assert cfg.consent_current is True
        assert cfg.consent_by == "testuser"
        assert resp.json()["consent_given"] is True

    def test_enable_with_existing_consent_no_restamp_needed(self, auth_client, configured):
        cfg = AISettings.get()
        cfg.record_consent("earlier")
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True})
        assert resp.status_code == 200
        assert AISettings.get().enabled is True
        assert AISettings.get().consent_by == "earlier"  # untouched

    def test_disable_always_succeeds_and_keeps_consent(self, auth_client, unconfigured):
        cfg = AISettings.get()
        cfg.record_consent("admin")
        cfg.enabled = True
        cfg.save()
        resp = _post(auth_client, "/api/ai/config/", {"enabled": False})
        assert resp.status_code == 200
        cfg.refresh_from_db()
        assert cfg.enabled is False
        assert cfg.consent_given_at is not None  # revocation != consent erasure

    def test_stale_consent_version_regates(self, auth_client, configured):
        from apps.core.ai.models import CURRENT_CONSENT_VERSION
        cfg = AISettings.get()
        cfg.record_consent("admin")
        cfg.consent_version = CURRENT_CONSENT_VERSION - 1
        cfg.enabled = False
        cfg.save()
        resp = _post(auth_client, "/api/ai/config/", {"enabled": True})
        assert resp.status_code == 400  # stale consent -> modal again


@pytest.mark.django_db
class TestCredentialSaving:
    def test_save_credentials_via_ui(self, auth_client, unconfigured):
        resp = _post(auth_client, "/api/ai/config/", {
            "enabled": False,
            "cloudflare_account_id": " ui-acct-77 ",
            "cloudflare_api_token": "ui-tok-88",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is True
        assert data["account_id_saved"] is True and data["api_token_saved"] is True
        cfg = AISettings.get()
        assert cfg.cloudflare_account_id == "ui-acct-77"  # stripped
        assert cfg.cloudflare_api_token == "ui-tok-88"

    def test_token_never_echoed_back(self, auth_client, unconfigured):
        _post(auth_client, "/api/ai/config/", {
            "enabled": False,
            "cloudflare_account_id": "SECRET-UI-ACCT",
            "cloudflare_api_token": "SECRET-UI-TOKEN",
        })
        body = auth_client.get("/api/ai/config/").content.decode()
        assert "SECRET-UI-ACCT" not in body
        assert "SECRET-UI-TOKEN" not in body

    def test_omitted_fields_leave_saved_values_unchanged(self, auth_client, unconfigured):
        cfg = AISettings.get()
        cfg.cloudflare_account_id = "keep-acct"
        cfg.cloudflare_api_token = "keep-tok"
        cfg.save()
        _post(auth_client, "/api/ai/config/", {"enabled": False})
        cfg.refresh_from_db()
        assert cfg.cloudflare_account_id == "keep-acct"
        assert cfg.cloudflare_api_token == "keep-tok"

    def test_empty_string_clears_and_falls_back_to_env(self, auth_client, configured):
        cfg = AISettings.get()
        cfg.cloudflare_api_token = "old-ui-tok"
        cfg.save()
        resp = _post(auth_client, "/api/ai/config/", {
            "enabled": False, "cloudflare_api_token": "",
        })
        data = resp.json()
        assert data["api_token_saved"] is False
        assert data["api_token_set"] is True  # env fallback still covers it

    def test_save_credentials_and_enable_in_one_call(self, auth_client, unconfigured):
        resp = _post(auth_client, "/api/ai/config/", {
            "enabled": True,
            "consent_accepted": True,
            "cloudflare_account_id": "a1",
            "cloudflare_api_token": "t1",
        })
        assert resp.status_code == 200
        assert AISettings.get().enabled is True


@pytest.mark.django_db
class TestTestEndpoint:
    def test_unconfigured_400(self, auth_client, unconfigured):
        assert _post(auth_client, "/api/ai/test/", {}).status_code == 400

    def test_success(self, auth_client, configured):
        with patch("apps.core.ai.client.chat_json", return_value={"text": "OK"}):
            resp = _post(auth_client, "/api/ai/test/", {})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "latency_ms" in data and "model" in data

    def test_failure_502(self, auth_client, configured):
        with patch("apps.core.ai.client.chat_json", return_value=None):
            resp = _post(auth_client, "/api/ai/test/", {})
        assert resp.status_code == 502

    def test_allowed_before_consent(self, auth_client, configured):
        assert AISettings.get().consent_given_at is None
        with patch("apps.core.ai.client.chat_json", return_value={"text": "OK"}):
            assert _post(auth_client, "/api/ai/test/", {}).status_code == 200


def _activate(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct"
    settings.CLOUDFLARE_API_TOKEN = "tok"
    cfg = AISettings.get()
    cfg.enabled = True
    cfg.save()
    cfg.record_consent("admin")


def _finished_session(status="completed"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status=status)


@pytest.mark.django_db
class TestTriageGet:
    def test_unknown_session_404(self, auth_client, configured):
        import uuid
        assert auth_client.get(f"/api/ai/triage/{uuid.uuid4()}/").status_code == 404

    def test_disabled_when_gate_closed(self, auth_client, unconfigured):
        sess = _finished_session()
        data = auth_client.get(f"/api/ai/triage/{sess.uuid}/").json()
        assert data["status"] == "disabled"

    def test_absent(self, auth_client, settings):
        _activate(settings)
        sess = _finished_session()
        data = auth_client.get(f"/api/ai/triage/{sess.uuid}/").json()
        assert data["status"] == "absent"
        assert data["decisions"] == []

    def test_complete_with_items(self, auth_client, settings):
        from apps.core.ai.models import AITriage
        from apps.core.findings.models import Finding
        _activate(settings)
        sess = _finished_session()
        f = Finding.objects.create(session=sess, source="nmap", check_type="cve",
                                   severity="critical", title="big", target="example.com")
        triage = AITriage.objects.create(session=sess, status="completed",
                                         overview="the overview", model="m")
        triage.items.create(finding=f, finding_key="nmap:cve:big", rank=1,
                            priority="fix_now", rationale="because")
        data = auth_client.get(f"/api/ai/triage/{sess.uuid}/").json()
        assert data["status"] == "complete"
        assert data["triage"]["summary"] == "the overview"
        item = data["triage"]["items"][0]
        assert item["finding_id"] == f.id
        assert item["severity"] == "critical"
        assert item["priority"] == "fix_now"

    def test_failed_and_running(self, auth_client, settings):
        from apps.core.ai.models import AITriage
        _activate(settings)
        sess = _finished_session()
        AITriage.objects.create(session=sess, status="failed")
        assert auth_client.get(f"/api/ai/triage/{sess.uuid}/").json()["status"] == "failed"
        AITriage.objects.filter(session=sess).update(status="running")
        assert auth_client.get(f"/api/ai/triage/{sess.uuid}/").json()["status"] == "running"


@pytest.mark.django_db
class TestTriageRun:
    def test_gate_closed_400(self, auth_client, unconfigured):
        sess = _finished_session()
        assert _post(auth_client, f"/api/ai/triage/{sess.uuid}/run/", {}).status_code == 400

    def test_scan_running_409(self, auth_client, settings):
        _activate(settings)
        sess = _finished_session(status="running")
        assert _post(auth_client, f"/api/ai/triage/{sess.uuid}/run/", {}).status_code == 409

    def test_in_flight_409(self, auth_client, settings):
        from apps.core.ai.models import AITriage
        _activate(settings)
        sess = _finished_session()
        AITriage.objects.create(session=sess, status="running")
        assert _post(auth_client, f"/api/ai/triage/{sess.uuid}/run/", {}).status_code == 409

    def test_enqueues_and_marks_running(self, auth_client, settings):
        from apps.core.ai.models import AITriage
        _activate(settings)
        sess = _finished_session()
        with patch("apps.core.ai.tasks.async_task") as enqueue:
            resp = _post(auth_client, f"/api/ai/triage/{sess.uuid}/run/", {})
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"
        enqueue.assert_called_once_with("apps.core.ai.tasks._run_triage_task", sess.id)
        assert AITriage.objects.get(session=sess).status == "running"


@pytest.mark.django_db
class TestTriageTask:
    def test_task_runs_triage_and_summaries(self, settings):
        from apps.core.ai.tasks import _run_triage_task
        _activate(settings)
        sess = _finished_session()
        with patch("apps.core.ai.triage.run_triage", return_value=object()) as triage, \
             patch("apps.core.ai.summaries.run_summaries") as summaries:
            _run_triage_task(sess.id)
        triage.assert_called_once()
        summaries.assert_called_once()

    def test_task_clears_marker_when_nothing_to_triage(self, settings):
        from apps.core.ai.models import AITriage
        from apps.core.ai.tasks import _run_triage_task
        _activate(settings)
        sess = _finished_session()
        AITriage.objects.create(session=sess, status="running")
        with patch("apps.core.ai.triage.run_triage", return_value=None), \
             patch("apps.core.ai.summaries.run_summaries"):
            _run_triage_task(sess.id)
        assert AITriage.objects.filter(session=sess).count() == 0

    def test_task_gate_closed_clears_marker(self, unconfigured):
        from apps.core.ai.models import AITriage
        from apps.core.ai.tasks import _run_triage_task
        sess = _finished_session()
        AITriage.objects.create(session=sess, status="running")
        _run_triage_task(sess.id)
        assert AITriage.objects.filter(session=sess).count() == 0

    def test_task_swallows_exceptions(self, settings):
        from apps.core.ai.tasks import _run_triage_task
        _activate(settings)
        sess = _finished_session()
        with patch("apps.core.ai.triage.run_triage", side_effect=RuntimeError("boom")):
            _run_triage_task(sess.id)  # must not raise


@pytest.mark.django_db
class TestAuditEndpoint:
    def test_requires_auth(self, client):
        assert client.get("/api/ai/audit/").status_code == 401

    def test_pagination_and_shape(self, auth_client, scan_session):
        for i in range(3):
            AIInvocation.objects.create(
                session=scan_session, session_uuid=scan_session.uuid,
                purpose="triage", model="m", status="ok",
                prompt_tokens=10 + i, completion_tokens=5, finding_ids=[1, 2],
            )
        resp = auth_client.get("/api/ai/audit/?page=1&page_size=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert len(data["results"]) == 2
        row = data["results"][0]
        assert row["domain"] == "example.com"
        assert row["finding_count"] == 2
        assert row["tokens_in"] == 12  # newest first
        # Metadata only — no body-like keys.
        assert not {"prompt", "response", "content", "message"} & set(row.keys())
