"""Unit tests for apps/core/ai/orchestrator.py — the bounded agent loop.

Covers safety invariants 2 (auth gate at the agent's dispatch boundary),
4 (guaranteed termination), 7 (sanctioned subscan path only), 8 (revocation
is terminal), and 9 (no Finding.status mutation).
"""

import pytest
from unittest.mock import patch

from apps.core.ai.models import AgentAction, AgentRun, AISettings
from apps.core.ai.orchestrator import run_agent_step


def _root(status="completed"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status=status)


def _finding(session, severity="high", title="t"):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, source="nmap", check_type="cve", severity=severity,
        title=title, target="example.com",
    )


def _authorize():
    from django.utils import timezone
    from apps.core.domains.models import Domain, DomainAuthorization
    dom, _ = Domain.objects.get_or_create(name="example.com", defaults={"is_active": True})
    DomainAuthorization.objects.get_or_create(
        domain=dom, defaults={"auth_type": "owner", "authorized_by": "t",
                              "authorized_at": timezone.now()})


@pytest.fixture
def active(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct"
    settings.CLOUDFLARE_API_TOKEN = "tok"
    cfg = AISettings.get()
    cfg.enabled = True
    cfg.save()
    cfg.record_consent("admin")
    return cfg


def _decide(*actions):
    return {"actions": list(actions)}


def _run_subscan(tools, reason="because"):
    return {"action": "run_subscan", "tools": tools, "reason": reason}


_DONE = {"action": "done", "summary": "all good"}


@pytest.mark.django_db
class TestGateAndRevocation:
    def test_gate_closed_marks_running_run_done(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = ""
        settings.CLOUDFLARE_API_TOKEN = ""
        root = _root()
        AgentRun.objects.create(root_session=root, status="running")
        with patch("apps.core.ai.orchestrator.client.chat_json") as call:
            run_agent_step(root.id)
        call.assert_not_called()
        run = AgentRun.objects.get()
        assert run.status == "done"
        assert "disabled" in run.final_summary

    def test_orchestration_subtoggle_off(self, active):
        active.orchestration_enabled = False
        active.save()
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json") as call:
            run_agent_step(root.id)
        call.assert_not_called()

    def test_terminal_run_never_restarts(self, active):
        root = _root()
        AgentRun.objects.create(root_session=root, status="done")
        with patch("apps.core.ai.orchestrator.client.chat_json") as call:
            run_agent_step(root.id)
        call.assert_not_called()
        assert AgentRun.objects.get().status == "done"


@pytest.mark.django_db
class TestTermination:
    def test_iteration_limit_reached(self, active):
        root = _root()
        AgentRun.objects.create(root_session=root, status="running",
                                iterations_used=active.max_agent_iterations)
        with patch("apps.core.ai.orchestrator.client.chat_json") as call:
            run_agent_step(root.id)
        call.assert_not_called()
        assert AgentRun.objects.get().status == "limit_reached"

    def test_iteration_consumed_before_llm_call(self, active):
        root = _root()

        def crash(*a, **kw):
            raise RuntimeError("mid-call crash")

        with patch("apps.core.ai.orchestrator.client.chat_json", side_effect=crash):
            with pytest.raises(RuntimeError):
                run_agent_step(root.id)
        assert AgentRun.objects.get().iterations_used == 1  # no free retry

    def test_llm_failure_is_terminal(self, active):
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json", return_value=None):
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        assert run.status == "failed"

    def test_done_action_ends_run(self, active):
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json", return_value=_decide(_DONE)):
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        assert run.status == "done"
        assert run.final_summary == "all good"
        assert run.actions.get().action_type == "done"

    def test_no_actionable_output_ends_run(self, active):
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json", return_value=_decide()):
            run_agent_step(root.id)
        assert AgentRun.objects.get().status == "done"

    def test_always_subscan_model_terminates_at_caps(self, active):
        """Invariant 4: a model that always wants another subscan is stopped by
        the iteration/subscan caps."""
        _authorize()
        root = _root()
        steps = 0
        with patch("apps.core.ai.orchestrator.client.chat_json") as call:
            # Fresh tools each step so the dedupe never short-circuits first.
            call.side_effect = [
                _decide(_run_subscan(["naabu"])),
                _decide(_run_subscan(["subfinder"])),
                _decide(_run_subscan(["httpx"])),
                _decide(_run_subscan(["katana"])),
            ]
            with patch("apps.core.ai.orchestrator.run_scan_task", create=True), \
                 patch("apps.core.scans.tasks.run_scan_task"):
                while AgentRun.objects.filter(root_session=root, status="running").exists() or steps == 0:
                    run_agent_step(root.id)
                    steps += 1
                    # Simulate each launched subscan completing so the chain would continue.
                    for sub in root.subscans.all():
                        if sub.status == "pending":
                            sub.status = "completed"
                            sub.save()
                    if steps > 10:
                        break
        run = AgentRun.objects.get()
        assert run.status in ("limit_reached", "done")
        assert run.subscans_launched <= active.max_subscans_per_scan
        assert run.iterations_used <= active.max_agent_iterations


@pytest.mark.django_db
class TestSubscanDispatch:
    def test_active_tools_denied_without_authorization(self, active):
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(_run_subscan(["naabu"]))):
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        assert run.status == "denied"
        action = run.actions.get()
        assert action.status == "denied"
        assert "DomainAuthorization" in action.denial_reason
        assert root.subscans.count() == 0  # invariant 2: no session created

    def test_authorized_subscan_launched_via_sanctioned_path(self, active):
        _authorize()
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(_run_subscan(["naabu"]))), \
             patch("apps.core.scans.tasks.async_task") as enqueue:
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        assert run.status == "running"  # waiting on the subscan
        assert run.subscans_launched == 1
        sub = root.subscans.get()
        assert sub.scan_type == "subscan"
        assert sub.triggered_by == "agent"  # invariant 7
        assert sub.subscan_tools == ["naabu"]
        enqueue.assert_called_once()
        assert run.actions.get().subscan_session_id == sub.id

    def test_passive_tools_need_no_authorization(self, active):
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(_run_subscan(["shodan"]))), \
             patch("apps.core.scans.tasks.async_task"):
            run_agent_step(root.id)
        assert AgentRun.objects.get().subscans_launched == 1

    def test_already_run_tools_noop(self, active):
        _authorize()
        root = _root()
        from apps.core.workflows.models import Workflow, WorkflowRun, WorkflowStepResult
        wf = Workflow.objects.create(name="t")
        wrun = WorkflowRun.objects.create(workflow=wf, session=root, status="completed")
        WorkflowStepResult.objects.create(run=wrun, tool="naabu", status="completed", order=1)
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(_run_subscan(["naabu"]))):
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        action = run.actions.get()
        assert action.status == "noop"
        assert "already ran" in action.denial_reason
        assert run.status == "done"  # nothing launched -> chain ends

    def test_only_one_subscan_per_step(self, active):
        root = _root()
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(_run_subscan(["shodan"]),
                                        _run_subscan(["subfinder"]))), \
             patch("apps.core.scans.tasks.async_task"):
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        assert run.subscans_launched == 1
        statuses = sorted(run.actions.values_list("status", flat=True))
        assert statuses == ["executed", "noop"]

    def test_subscan_budget_exhausted_noop(self, active):
        root = _root()
        AgentRun.objects.create(root_session=root, status="running",
                                subscans_launched=active.max_subscans_per_scan)
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(_run_subscan(["shodan"]))):
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        assert run.actions.get().denial_reason == "subscan budget exhausted"
        assert run.status == "done"

    def test_partial_parent_cannot_spawn_subscan(self, active):
        root = _root(status="partial")
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(_run_subscan(["shodan"]))):
            run_agent_step(root.id)
        run = AgentRun.objects.get()
        assert run.actions.get().status == "failed"
        assert root.subscans.count() == 0


@pytest.mark.django_db
class TestFlagFinding:
    def test_flag_never_mutates_finding_status(self, active):
        root = _root()
        f = _finding(root)
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(
                       {"action": "flag_finding", "finding_id": f.id, "note": "look"},
                       _DONE)):
            run_agent_step(root.id)
        f.refresh_from_db()
        assert f.status == "open"  # invariant 9
        flag = AgentAction.objects.get(action_type="flag_finding")
        assert flag.status == "executed"
        assert flag.payload == {"finding_id": f.id}

    def test_flag_foreign_finding_noop(self, active):
        root = _root()
        other = _root()
        f = _finding(other)
        with patch("apps.core.ai.orchestrator.client.chat_json",
                   return_value=_decide(
                       {"action": "flag_finding", "finding_id": f.id, "note": "x"},
                       _DONE)):
            run_agent_step(root.id)
        flag = AgentAction.objects.filter(action_type="flag_finding").get()
        assert flag.status == "noop"


@pytest.mark.django_db
class TestChainHooks:
    def test_finalize_enqueues_agent_for_root(self, active):
        from apps.core.scans.pipeline import _finalize_session
        root = _root(status="running")
        _finding(root)
        with patch("apps.core.ai.client.chat_json", return_value=None), \
             patch("apps.core.ai.tasks.async_task") as enqueue:
            _finalize_session(root)
        enqueue.assert_any_call("apps.core.ai.tasks._run_agent_step", root.id)

    def test_subscan_finalize_resumes_running_chain(self, active):
        from apps.core.scans.pipeline import _finalize_session
        root = _root()
        run = AgentRun.objects.create(root_session=root, status="running")
        from apps.core.scans.models import ScanSession
        sub = ScanSession.objects.create(
            domain="example.com", scan_type="subscan", parent_session=root,
            status="running", subscan_tools=["shodan"],
        )
        AgentAction.objects.create(agent_run=run, iteration=1,
                                   action_type="run_subscan", status="executed",
                                   subscan_session=sub)
        with patch("apps.core.ai.tasks.async_task") as enqueue:
            _finalize_session(sub)
        enqueue.assert_called_once_with("apps.core.ai.tasks._run_agent_step", root.id)

    def test_unrelated_subscan_does_not_resume(self, active):
        from apps.core.scans.pipeline import _finalize_session
        root = _root()
        from apps.core.scans.models import ScanSession
        sub = ScanSession.objects.create(
            domain="example.com", scan_type="subscan", parent_session=root,
            status="running",
        )
        with patch("apps.core.ai.tasks.async_task") as enqueue:
            _finalize_session(sub)
        enqueue.assert_not_called()

    def test_no_agent_for_manual_subscan_root(self, active):
        from apps.core.ai.hooks import maybe_start_agent
        from apps.core.scans.models import ScanSession
        sub = ScanSession.objects.create(
            domain="example.com", scan_type="subscan", status="completed",
        )
        with patch("apps.core.ai.tasks.async_task") as enqueue:
            maybe_start_agent(sub)
        enqueue.assert_not_called()
