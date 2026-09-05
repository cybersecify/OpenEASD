"""Adaptive scan orchestration — the bounded agent loop.

One step = exactly one LLM decision call plus bookkeeping. Steps are chained
through Django-Q: a step that launches a subscan returns immediately, and the
subscan's finalize re-enqueues the next step (hooks.maybe_continue_agent).
Nothing ever waits on another task, so the single worker cannot deadlock.

Termination is guaranteed on every path (safety invariant 4):
  * iterations_used is incremented and persisted BEFORE the LLM call, so a
    crashed step still consumes its iteration;
  * at most one subscan per step, capped by max_subscans_per_scan;
  * failure, denial, and consent revocation are terminal;
  * a step that launches nothing ends the run.

The authorization boundary is guard.gate_subscan_tools (invariant 2): the
agent can only reach a target through create_subscan_session, and only after
the same DomainAuthorization check the manual API enforces.
"""

import logging

from django.utils import timezone

from . import client, context
from .guard import gate_subscan_tools, is_ai_active
from .models import AgentAction, AgentRun, AISettings
from .schemas import AgentDecision

logger = logging.getLogger(__name__)


def _finish(run: AgentRun, status: str, summary: str = "") -> None:
    run.status = status
    run.finished_at = timezone.now()
    if summary:
        run.final_summary = summary
    run.save(update_fields=["status", "finished_at", "final_summary"])
    logger.info("[ai:agent:%s] run finished — %s", run.root_session_id, status)


def run_agent_step(root_session_id: int) -> None:
    """Execute one orchestration step for the root session. Never raises."""
    from apps.core.scans.models import ScanSession

    session = ScanSession.objects.filter(id=root_session_id).first()
    if session is None:
        return

    cfg = AISettings.get()
    if not is_ai_active() or not cfg.orchestration_enabled:
        # Revocation mid-chain is terminal (D-013 4d): no new calls, ever.
        updated = AgentRun.objects.filter(
            root_session=session, status="running"
        ).update(status="done", finished_at=timezone.now(),
                 final_summary="stopped: analysis disabled")
        if updated:
            logger.info("[ai:agent:%s] chain stopped — gate closed", session.id)
        return

    run, _ = AgentRun.objects.get_or_create(root_session=session)
    if run.status != "running":
        return  # already terminal — a stale queue entry must not restart it

    if run.iterations_used >= cfg.max_agent_iterations:
        _finish(run, "limit_reached")
        return

    # Consume the iteration BEFORE the LLM call — a crash mid-step must not
    # grant a free retry, or the loop bound is meaningless.
    run.iterations_used += 1
    run.save(update_fields=["iterations_used"])
    iteration = run.iterations_used

    messages = context.build_orchestration_messages(session, run, cfg)
    out = client.chat_json(
        messages, AgentDecision, purpose="orchestration", session=session,
    )
    if out is None:
        _finish(run, "failed", "analysis backend unavailable")
        return

    launched_subscan = False
    for action in out.get("actions", [])[:5]:
        kind = action.get("action")
        if kind == "done":
            AgentAction.objects.create(
                agent_run=run, iteration=iteration, action_type="done",
                rationale=action.get("summary", ""), status="executed",
            )
            _finish(run, "done", action.get("summary", ""))
            return
        if kind == "flag_finding":
            _handle_flag(run, iteration, session, action)
        elif kind == "run_subscan":
            if launched_subscan:
                AgentAction.objects.create(
                    agent_run=run, iteration=iteration, action_type="run_subscan",
                    payload={"tools": action.get("tools", [])},
                    rationale=action.get("reason", ""), status="noop",
                    denial_reason="only one subscan per step",
                )
                continue
            outcome = _handle_subscan(run, iteration, session, cfg, action)
            if outcome == "denied":
                return  # _handle_subscan already finished the run
            launched_subscan = outcome == "launched"

    if launched_subscan:
        return  # chain resumes when the subscan finalizes

    # Nothing actionable happened this step — the chain has no wake-up signal
    # left, so the run must end here or it would dangle as "running" forever.
    _finish(run, "done", run.final_summary or "no further scanning needed")


def _handle_flag(run: AgentRun, iteration: int, session, action: dict) -> None:
    """flag_finding writes an attention marker ONLY — the agent never mutates
    Finding.status (lifecycle changes stay human-only, invariant 9)."""
    from apps.core.findings.models import Finding

    finding_id = action.get("finding_id")
    session_ids = [session.id, *session.subscans.values_list("id", flat=True)]
    valid = Finding.objects.filter(id=finding_id, session_id__in=session_ids).exists()
    AgentAction.objects.create(
        agent_run=run, iteration=iteration, action_type="flag_finding",
        payload={"finding_id": finding_id},
        rationale=action.get("note", ""),
        status="executed" if valid else "noop",
        denial_reason="" if valid else "finding not in this scan",
    )


def _handle_subscan(run: AgentRun, iteration: int, session, cfg, action: dict) -> str:
    """Returns 'launched', 'denied' (terminal, run already finished), or 'noop'."""
    from apps.core.scans.pipeline import create_subscan_session
    from apps.core.scans.tasks import run_scan_task

    proposed = [t for t in action.get("tools", []) if isinstance(t, str)]
    reason = action.get("reason", "")

    if run.subscans_launched >= cfg.max_subscans_per_scan:
        AgentAction.objects.create(
            agent_run=run, iteration=iteration, action_type="run_subscan",
            payload={"tools": proposed}, rationale=reason, status="noop",
            denial_reason="subscan budget exhausted",
        )
        return "noop"

    already = set(context.tools_already_run(session))
    fresh = [t for t in proposed if t not in already]
    if not fresh:
        AgentAction.objects.create(
            agent_run=run, iteration=iteration, action_type="run_subscan",
            payload={"tools": proposed}, rationale=reason, status="noop",
            denial_reason="all proposed tools already ran",
        )
        return "noop"

    allowed, denial = gate_subscan_tools(session.domain, fresh)
    if not allowed:
        # A denied dispatch is terminal — retrying against the gate would just
        # ping-pong. The denial is user-visible on the scan detail page.
        AgentAction.objects.create(
            agent_run=run, iteration=iteration, action_type="run_subscan",
            payload={"tools": fresh}, rationale=reason, status="denied",
            denial_reason=denial[:200],
        )
        _finish(run, "denied", denial)
        return "denied"

    sub = create_subscan_session(str(session.uuid), allowed, triggered_by="agent")
    if sub is None:
        AgentAction.objects.create(
            agent_run=run, iteration=iteration, action_type="run_subscan",
            payload={"tools": allowed}, rationale=reason, status="failed",
            denial_reason="could not create subscan (parent not completed)",
        )
        return "noop"

    run_scan_task(sub.id)
    AgentAction.objects.create(
        agent_run=run, iteration=iteration, action_type="run_subscan",
        payload={"tools": allowed}, rationale=reason, status="executed",
        subscan_session=sub,
    )
    run.subscans_launched += 1
    run.save(update_fields=["subscans_launched"])
    logger.info("[ai:agent:%s] launched subscan %s with %s",
                session.id, sub.uuid, allowed)
    return "launched"
