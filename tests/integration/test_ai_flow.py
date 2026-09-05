"""Integration tests — the AI layer end-to-end through the real pipeline.

Unlike the per-module unit suites, these mock ONLY the Cloudflare HTTP edge
(requests.post) and the Django-Q queue (run tasks synchronously), so every
real seam is exercised: _finalize_session → hooks → triage/summaries →
client envelope parsing + audit → orchestration chain → subscan creation →
report context → alert payload.

The last class is an OPT-IN live smoke test: it makes one real Workers AI
call and only runs when CLOUDFLARE_ACCOUNT_ID/CLOUDFLARE_API_TOKEN are in
the process environment (never in CI).
"""

import os

import pytest
from unittest.mock import MagicMock, patch

from apps.core.ai.models import (
    AgentRun,
    AIInvocation,
    AISettings,
    AISummary,
    AITriage,
)
from apps.core.scans.pipeline import _finalize_session


# ---------------------------------------------------------------------------
# Fake Cloudflare Workers AI
# ---------------------------------------------------------------------------

def _envelope(response_obj):
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {}
    resp.json.return_value = {
        "success": True,
        "result": {
            "response": response_obj,
            "usage": {"prompt_tokens": 900, "completion_tokens": 150, "total_tokens": 1050},
        },
        "errors": [],
    }
    return resp


def _fake_cloudflare(finding_ids, orchestration_script):
    """requests.post side_effect that answers by schema shape:
    TriageOut has 'items', AgentDecision has 'actions', SummaryOut has 'text'.
    orchestration_script is a list of AgentDecision dicts consumed in order."""
    script = list(orchestration_script)

    def responder(url, json=None, headers=None, timeout=None):
        props = json["response_format"]["json_schema"].get("properties", {})
        if "items" in props:
            return _envelope({
                "overview": "One issue dominates this surface.",
                "items": [
                    {"finding_id": fid, "priority": "fix_now", "rationale": "internet-facing"}
                    for fid in finding_ids
                ],
            })
        if "actions" in props:
            return _envelope(script.pop(0) if script else {"actions": [
                {"action": "done", "summary": "nothing left to check"}]})
        return _envelope({"text": "Plain-language summary of the scan."})

    return responder


def _run_ai_queue_inline():
    """Patch the AI queue so enqueued tasks execute synchronously."""
    from apps.core.ai import tasks

    def inline(path, arg):
        {"apps.core.ai.tasks._run_triage_task": tasks._run_triage_task,
         "apps.core.ai.tasks._run_agent_step": tasks._run_agent_step}[path](arg)

    return patch("apps.core.ai.tasks.async_task", side_effect=inline)


def _activate(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct"
    settings.CLOUDFLARE_API_TOKEN = "tok"
    cfg = AISettings.get()
    cfg.enabled = True
    cfg.save()
    cfg.record_consent("admin")
    return cfg


def _root_session(status="running"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status=status)


def _finding(session, title="Exposed admin panel", severity="critical"):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, source="nuclei", check_type="exposure", severity=severity,
        title=title, target="admin.example.com", description="d", remediation="r",
    )


# ---------------------------------------------------------------------------
# Happy path: scan → triage → summaries → report/alert → agent completes
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAiFullFlow:
    def test_finalize_produces_triage_summaries_agent_and_audit(self, settings):
        _activate(settings)
        sess = _root_session()
        f = _finding(sess)

        responder = _fake_cloudflare(
            [f.id], orchestration_script=[
                {"actions": [{"action": "done", "summary": "surface fully covered"}]},
            ])
        with patch("apps.core.ai.client.requests.post", side_effect=responder), \
             _run_ai_queue_inline(), \
             patch("apps.core.scans.pipeline._dispatch_alerts"):
            _finalize_session(sess)

        # Scan itself unaffected.
        sess.refresh_from_db()
        assert sess.status == "completed"
        assert sess.total_findings == 1

        # Triage: ranked item linked to the real finding.
        triage = AITriage.objects.get(session=sess)
        assert triage.status == "completed"
        assert triage.overview == "One issue dominates this surface."
        item = triage.items.get()
        assert item.finding_id == f.id
        assert item.priority == "fix_now"

        # Summaries: both kinds.
        assert set(AISummary.objects.filter(session=sess)
                   .values_list("kind", flat=True)) == {"report", "alert"}

        # Agent: ran synchronously and finished with 'done'.
        run = AgentRun.objects.get(root_session=sess)
        assert run.status == "done"
        assert run.final_summary == "surface fully covered"

        # Audit: one metadata-only row per call, tokens recorded.
        purposes = sorted(AIInvocation.objects.values_list("purpose", flat=True))
        assert purposes == ["alert_summary", "orchestration", "report_summary", "triage"]
        for row in AIInvocation.objects.all():
            assert row.status == "ok"
            assert row.total_tokens == 1050
            assert row.session_uuid == sess.uuid

    def test_report_and_alert_carry_the_ai_output(self, settings):
        from apps.core.notifications.dispatcher import _build_slack_payload
        from apps.core.reports.views import _ai_context

        _activate(settings)
        sess = _root_session()
        f = _finding(sess)
        responder = _fake_cloudflare([f.id], orchestration_script=[])
        with patch("apps.core.ai.client.requests.post", side_effect=responder), \
             _run_ai_queue_inline(), \
             patch("apps.core.scans.pipeline._dispatch_alerts"):
            _finalize_session(sess)

        ctx = _ai_context(sess)
        assert ctx["ai_summary"] == "Plain-language summary of the scan."
        assert ctx["ai_triage_top"][0]["title"] == "Exposed admin panel"

        grouped = {"critical": [{"title": f.title, "check_type": f.check_type,
                                 "target": f.target}]}
        payload = _build_slack_payload(sess, grouped, "high")
        assert any("Plain-language summary" in str(b) for b in payload["blocks"])


# ---------------------------------------------------------------------------
# Agent chain: launch a subscan, resume on its finalize, then stop
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAgentChainFlow:
    def test_subscan_roundtrip(self, settings):
        _activate(settings)
        sess = _root_session()
        f = _finding(sess)

        responder = _fake_cloudflare(
            [f.id], orchestration_script=[
                {"actions": [{"action": "run_subscan", "tools": ["shodan"],
                              "reason": "passive exposure check"}]},
                {"actions": [{"action": "done", "summary": "shodan added nothing new"}]},
            ])

        with patch("apps.core.ai.client.requests.post", side_effect=responder), \
             _run_ai_queue_inline(), \
             patch("apps.core.scans.tasks.async_task"), \
             patch("apps.core.scans.pipeline._dispatch_alerts"):
            _finalize_session(sess)

            # Step 1 launched a passive subscan through the sanctioned path.
            run = AgentRun.objects.get(root_session=sess)
            assert run.status == "running"
            sub = sess.subscans.get()
            assert sub.triggered_by == "agent"
            assert sub.subscan_tools == ["shodan"]

            # Simulate the subscan's worker run finishing → its finalize
            # resumes the chain, which now answers 'done'.
            sub.status = "running"
            sub.save()
            _finalize_session(sub)

        run.refresh_from_db()
        assert run.status == "done"
        assert run.final_summary == "shodan added nothing new"
        assert run.iterations_used == 2
        assert run.subscans_launched == 1
        actions = list(run.actions.order_by("id").values_list("action_type", "status"))
        assert actions == [("run_subscan", "executed"), ("done", "executed")]


# ---------------------------------------------------------------------------
# Off and broken: the scan must be indistinguishable from AI never existing
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAiOffAndBrokenFlow:
    def test_ai_off_leaves_zero_traces(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = ""
        settings.CLOUDFLARE_API_TOKEN = ""
        sess = _root_session()
        _finding(sess)
        with patch("apps.core.ai.client.requests.post") as post, \
             patch("apps.core.scans.pipeline._dispatch_alerts"):
            _finalize_session(sess)
        post.assert_not_called()
        assert AIInvocation.objects.count() == 0
        assert AITriage.objects.count() == 0
        assert AgentRun.objects.count() == 0
        sess.refresh_from_db()
        assert sess.status == "completed"

    def test_cloudflare_hard_down_scan_still_completes(self, settings):
        _activate(settings)
        sess = _root_session()
        _finding(sess)
        down = MagicMock(status_code=500, headers={})
        with patch("apps.core.ai.client.requests.post", return_value=down), \
             patch("apps.core.ai.client.time.sleep"), \
             _run_ai_queue_inline(), \
             patch("apps.core.scans.pipeline._dispatch_alerts") as alerts:
            _finalize_session(sess)

        sess.refresh_from_db()
        assert sess.status == "completed"          # scan outcome untouched
        alerts.assert_called_once()                # alerts still dispatched
        assert AITriage.objects.get(session=sess).status == "failed"
        assert AISummary.objects.count() == 0
        assert AgentRun.objects.get(root_session=sess).status == "failed"
        assert set(AIInvocation.objects.values_list("status", flat=True)) == {"http_error"}


# ---------------------------------------------------------------------------
# Live smoke test — opt-in, real credentials, ONE real call
# ---------------------------------------------------------------------------

_LIVE = bool(os.environ.get("CLOUDFLARE_ACCOUNT_ID") and os.environ.get("CLOUDFLARE_API_TOKEN"))


@pytest.mark.skipif(not _LIVE, reason="set CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN to run the live smoke test")
@pytest.mark.django_db
class TestLiveCloudflareSmoke:
    """Answers 'is it actually working?' against the real API. Sends a fixed
    prompt (no scan data), like the /api/ai/test/ endpoint. Run with:
        uv run pytest tests/integration/test_ai_flow.py -k live -v
    """

    def test_live_structured_call_round_trips(self, settings):
        from apps.core.ai import client
        from apps.core.ai.schemas import SummaryOut

        settings.CLOUDFLARE_ACCOUNT_ID = os.environ["CLOUDFLARE_ACCOUNT_ID"]
        settings.CLOUDFLARE_API_TOKEN = os.environ["CLOUDFLARE_API_TOKEN"]

        out = client.chat_json(
            [{"role": "user", "content": 'Reply with exactly this JSON object: {"text": "OK"}'}],
            SummaryOut, purpose="test", max_tokens=50,
        )
        assert out is not None, "live Workers AI call failed — check credentials/model"
        assert isinstance(out.get("text"), str) and out["text"]
        row = AIInvocation.objects.get()
        assert row.status == "ok"
        assert row.purpose == "test"
