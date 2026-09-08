"""Tests for the @durable_task engine adapter (PQC hardening H6)."""

from unittest.mock import MagicMock, patch

from apps.core.engine.durable.task import DurableTask, REGISTRY, durable_task


def test_in_process_call_runs_body_without_dbos():
    """task(*args) runs the body directly — no DBOS engine needed."""
    calls = []

    @durable_task("t_inproc")
    def t(x):
        calls.append(x)
        return x * 2

    assert t(21) == 42
    assert calls == [21]


def test_registry_registration():
    @durable_task("t_reg")
    def t():
        return None

    assert REGISTRY["t_reg"] is t
    assert isinstance(t, DurableTask)
    assert t.name == "t_reg"


def test_delay_enqueues_with_name_and_queue():
    @durable_task("t_delay", queue="scans")
    def t(x):
        return None

    fake_client = MagicMock()
    fake_client.enqueue.return_value = MagicMock(workflow_id="wf-1")
    with patch("apps.core.engine.durable.dbos_app.get_client", return_value=fake_client):
        wid = t.delay(7)

    assert wid == "wf-1"
    opts, arg = fake_client.enqueue.call_args[0]
    assert opts["workflow_name"] == "t_delay"
    assert opts["queue_name"] == "scans"
    assert "deduplication_id" not in opts  # no dedupe template → no dedup id
    assert arg == 7


def test_delay_uses_dedupe_template():
    @durable_task("t_dedupe", dedupe="triage-{0}")
    def t(x):
        return None

    fake_client = MagicMock()
    fake_client.enqueue.return_value = MagicMock(workflow_id="wf-2")
    with patch("apps.core.engine.durable.dbos_app.get_client", return_value=fake_client):
        t.delay(99)

    opts = fake_client.enqueue.call_args[0][0]
    assert opts["deduplication_id"] == "triage-99"
    assert opts["duplication_policy"] == "return-existing"


def test_delay_dedupe_id_override_wins():
    @durable_task("t_override", dedupe="x-{0}")
    def t(x):
        return None

    fake_client = MagicMock()
    fake_client.enqueue.return_value = MagicMock(workflow_id="w")
    with patch("apps.core.engine.durable.dbos_app.get_client", return_value=fake_client):
        t.delay(1, dedupe_id="custom-id")

    assert fake_client.enqueue.call_args[0][0]["deduplication_id"] == "custom-id"


def test_real_tasks_are_durable_tasks_with_expected_names():
    """The converted one-step tasks keep their DBOS workflow names + dedup."""
    from apps.core.engine.durable import workflows

    assert isinstance(workflows.ai_triage, DurableTask)
    assert workflows.ai_triage.name == "ai_triage"
    assert workflows.ai_triage._dedupe == "triage-{0}"

    assert isinstance(workflows.agent_step, DurableTask)
    assert workflows.agent_step.name == "agent_step"
    assert workflows.agent_step._dedupe is None


def test_enqueue_wrappers_delegate_to_delay():
    """The kept enqueue_* helpers route through the task's .delay()."""
    from apps.core.engine.durable import workflows

    with patch.object(workflows.ai_triage, "delay", return_value="wid-t") as m_t:
        assert workflows.enqueue_ai_triage(5) == "wid-t"
        m_t.assert_called_once_with(5)

    with patch.object(workflows.agent_step, "delay", return_value="wid-a") as m_a:
        assert workflows.enqueue_agent_step(9) == "wid-a"
        m_a.assert_called_once_with(9)
