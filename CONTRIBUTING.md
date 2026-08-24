# Contributing to OpenEASD

Thanks for contributing. **One rule for everyone — internal team and external
contributors alike: all changes land on `main` through a reviewed pull request.
Nobody pushes to `main` directly.** Branch protection enforces this.

## The flow at a glance

1. Branch (or fork) → 2. commit → 3. open a PR → 4. CI must pass → 5. one
approval from someone other than the author → 6. squash-merge → 7. delete the
branch.

## Internal team (you have write access)

- Create a branch **in this repo**:
  - `feat/<short-name>` — new user-facing feature
  - `fix/<short-name>` — bug fix, deps, config, refactor, docs, cleanup
- Commit with a conventional prefix (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`,
  `test:` — use the most specific one that fits).
- Open a PR against `main`. CI runs automatically.
- Get **one approval from another team member** (you cannot approve your own PR).
  `CODEOWNERS` auto-requests the right reviewer for the area you touched.
- **Squash-merge** and delete the branch.
- Do **not** self-merge without a review, and treat admin-override as an
  emergency-only escape hatch — the second set of eyes is the point.

## External contributors (no write access)

- **Fork** the repo, branch in your fork, and open a PR from your fork against
  `main`. (You cannot push branches to this repo — that's the security boundary.)
- A maintainer will review. External PRs get extra scrutiny; CI runs without
  access to repository secrets (by design), so it validates safely.
- A maintainer merges once CI is green and the review is done.
- For anything non-trivial, open an issue first so we can agree on the approach
  before you invest the work.

## What every PR must satisfy (branch-protection rules on `main`)

- Opened as a PR (no direct pushes to `main`).
- **CI status checks pass** — Test & Security Scan, Frontend Build, Docker Build,
  and the CodeQL Analyze jobs.
- **At least 1 approving review** from a non-author. Stale approvals are
  dismissed when new commits are pushed.
- Branch is up to date with `main` before merging.

## Local checks before you push

```bash
uv run manage.py check
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py   # fast suite
cd frontend && npm run build                                       # if you touched the SPA
```

## Definition of done for adding/removing a scan tool

Adding a tool touches more than its own app — see the checklist in `CLAUDE.md`
("Definition of done for adding (or removing) a tool"): register it, add it to
the default Full Scan migration, update the tool count + list + pipeline diagram
in `README.md`, update `CHANGELOG.md` and `CLAUDE.md`. CI's
`test_default_workflow.py` invariant fails if a registered tool isn't in Full
Scan, so keep them in sync.
