<!--
Thanks for the PR. Quick checklist below — not exhaustive, just the
common things reviewers will check first. See CONTRIBUTING.md if
anything's unclear.
-->

> **First time contributing?** CI won't run automatically on PRs from new accounts — that's our anti-spam gate, not unresponsiveness. A maintainer will approve it within a few hours, up to 2 business days depending on load.

> **About contributions:** OpenEASD is MIT-licensed open source maintained by Cybersecify (Rathnakara G N + Ashok S Kamat). Community contributions are welcomed — they make the project move faster and amplify what we can give back to the security community. We don't pay for PRs or run a bug bounty program; contributions are recognised through public CHANGELOG credit, commit attribution, GitHub Discussion shout-outs, and (where applicable) conference / publication co-credit. See [SECURITY.md](https://github.com/cybersecify/OpenEASD/blob/main/SECURITY.md) for the no-bounty note and [CONTRIBUTING.md](https://github.com/cybersecify/OpenEASD/blob/main/CONTRIBUTING.md) for what we look for in a PR.

## Type of change

- [ ] Bug fix
- [ ] New feature / new tool
- [ ] Refactor (no behavior change)
- [ ] Docs / tests only

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
