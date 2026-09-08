"""`@durable_task` — a thin adapter over DBOS (pipeline principle #11).

Keeps a task body free of any `dbos` import: the decorator registers the body as
a **one-step DBOS workflow** (so the worker executes, checkpoints, and resumes it)
and exposes a small, uniform surface:

    task(*args)                 run the body NOW, in-process — no DBOS engine
                                needed (tests, or a deliberate inline call)
    task.delay(*args)           durably enqueue the task's DBOS workflow on its
                                queue (dedup id derived from `dedupe` if set)
    task.delay(*args, dedupe_id="…")   override the dedup id per call

Design boundary: this adapter is for **one-step** tasks (ai_triage, agent_step,
hygiene jobs). `run_scan` stays an explicit *multi-step* `@DBOS.workflow` in
`workflows.py` because its per-phase checkpointing (resume at the first unfinished
phase) is the whole point of the durable engine — collapsing it into a one-step
task would lose that. See docs/specs/2026-09-07-producer-queue-consumer-hardening.md
(H6).

Registration timing mirrors the previous explicit decorators exactly: the DBOS
workflow/step are built when the defining module (`workflows.py`) is imported,
which in the worker happens right after `configure_dbos()` constructs the engine.
The web process never imports `workflows.py`; it enqueues by name via `get_client`,
so `.delay()` works there without any DBOS decorator having run.
"""

from __future__ import annotations

import functools
import logging
from typing import Callable

from .constants import QUEUE_NAME

logger = logging.getLogger(__name__)

# name -> DurableTask, for introspection/tests and any registry-driven dispatch.
REGISTRY: dict[str, "DurableTask"] = {}


class DurableTask:
    """A callable that runs in-process, plus `.delay()` to durably enqueue."""

    def __init__(self, func: Callable, name: str, queue: str, dedupe: str | None):
        self._func = func
        self.name = name
        self.queue = queue
        self._dedupe = dedupe  # e.g. "triage-{0}" (str.format over positional args)
        functools.update_wrapper(self, func)
        # Build the DBOS one-step workflow now, exactly as the old explicit
        # @DBOS.workflow/@DBOS.step did (same import-time registration). Guarded so
        # importing this module where `dbos` is unavailable degrades to
        # in-process-only (the body + .delay-by-name still work via the client).
        self._dbos_workflow = self._register_dbos_workflow()

    def _register_dbos_workflow(self):
        try:
            from dbos import DBOS
        except Exception:  # noqa: BLE001 — no engine available; in-process still works
            return None

        step = DBOS.step()(self._func)

        @DBOS.workflow(name=self.name)
        @functools.wraps(self._func)
        def _workflow(*args, **kwargs):
            return step(*args, **kwargs)

        return _workflow

    def __call__(self, *args, **kwargs):
        """Run the task body NOW, in-process. No DBOS engine involved."""
        return self._func(*args, **kwargs)

    def _resolve_dedupe_id(self, args, dedupe_id):
        if dedupe_id is not None:
            return dedupe_id
        if self._dedupe:
            return self._dedupe.format(*args)
        return None

    def delay(self, *args, dedupe_id: str | None = None) -> str:
        """Durably enqueue this task's DBOS workflow; returns the workflow id."""
        from dbos import EnqueueOptions

        from .client import get_client

        options: EnqueueOptions = {
            "workflow_name": self.name,
            "queue_name": self.queue,
        }
        did = self._resolve_dedupe_id(args, dedupe_id)
        if did:
            options["deduplication_id"] = did
            options["duplication_policy"] = "return-existing"
        handle = get_client().enqueue(options, *args)
        return handle.workflow_id


def durable_task(name: str, *, queue: str = QUEUE_NAME, dedupe: str | None = None):
    """Register `func` as a durable task named `name`.

    `dedupe` is an optional `str.format` template over the call's positional args
    (e.g. "triage-{0}") — when set, `.delay()` uses it as the DBOS
    `deduplication_id` with `return-existing`, so the same work is never enqueued
    twice concurrently (pipeline principle #5).
    """

    def decorator(func: Callable) -> DurableTask:
        task = DurableTask(func, name=name, queue=queue, dedupe=dedupe)
        REGISTRY[name] = task
        return task

    return decorator
