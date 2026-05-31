<!--
Thanks for the PR. Quick checklist below — not exhaustive, just the
common things reviewers will check first. See CONTRIBUTING.md if
anything's unclear.
-->

## What this changes

<!-- 1-3 sentences. The "why" matters more than the "what" — the diff
shows the what. -->

## Linked issue

<!-- Closes #123 / Refs #456. If no issue exists, add a sentence
explaining motivation. -->

## How to test

<!-- Step-by-step or commands. If the change adds a new tool, include
the workflow + scan target you ran it against. -->

```bash
# example
uv run pytest tests/unit/test_<thing>.py -v
```

## Checklist

- [ ] `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py` passes locally
- [ ] If you added/changed a tool collector, you updated `tests/unit/test_<tool>.py`
- [ ] If you changed customer-facing claims, you ran the README claims-trace mental check (every claim still maps to code)
- [ ] If you added a dependency, you noted it in the PR description with the reason
- [ ] CHANGELOG.md updated under `[Unreleased]` with a *why* note for anything user-visible

## Anything reviewers should look at first

<!-- Tricky bits, design trade-offs you made, things you weren't sure
about. Be honest about uncertainty — it speeds up review. -->
