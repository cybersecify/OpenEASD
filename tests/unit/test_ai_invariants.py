"""Source-level AI safety invariants (grep-style, keep cheap and strict).

These complement the behavioral tests: they fail the moment someone adds a
code path that could violate the no-lifecycle-mutation or no-bodies rules,
even if no behavioral test happens to exercise it.
"""

import re
from pathlib import Path

AI_DIR = Path(__file__).resolve().parents[2] / "apps" / "core" / "ai"


def _ai_sources() -> dict[str, str]:
    return {p.name: p.read_text() for p in AI_DIR.glob("*.py")}


def test_ai_subsystem_never_writes_findings():
    """Invariant 9: the AI layer reads Finding rows but never creates,
    updates, or deletes them — lifecycle changes stay human-only."""
    allowed = re.compile(r"Finding\.objects\.filter\b")
    any_use = re.compile(r"Finding\.objects\.\w+")
    for name, src in _ai_sources().items():
        for match in any_use.finditer(src):
            assert allowed.match(src, match.start()), (
                f"{name} uses {match.group()!r} — the AI subsystem may only "
                "Finding.objects.filter(...)"
            )


def test_audit_writer_takes_no_body_parameters():
    """Invariant 3, structurally: the audit writer's signature has no
    parameter that could carry prompt or response text."""
    import inspect

    from apps.core.ai.client import _audit

    params = set(inspect.signature(_audit).parameters)
    forbidden = {"prompt", "response", "messages", "content", "body", "text"}
    assert not params & forbidden, f"audit writer grew body-like params: {params & forbidden}"


def test_no_response_text_persisted_by_client():
    """The client module must never hand response body text to the ORM: the
    only .create( call allowed in client.py is the AIInvocation audit row."""
    src = _ai_sources()["client.py"]
    creates = re.findall(r"(\w+)\.objects\.create", src)
    assert creates in ([], ["AIInvocation"]), creates
