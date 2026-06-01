# Contributing to OpenEASD

Thanks for thinking about contributing. OpenEASD is built by a small team
and we genuinely want help. This doc covers how to get in.

## Quickest contribution path: add a new tool

This is the easiest way to make a meaningful PR. The workflow runner is
plugin-based — tools self-register via their Django `AppConfig.tool_meta`
and the registry auto-discovers them. **No core files change** when you
add one.

```python
# apps/my_tool/apps.py
from django.apps import AppConfig

class MyToolConfig(AppConfig):
    name = "apps.my_tool"
    label = "my_tool"
    verbose_name = "My Tool"
    tool_meta = {
        "label": "My Tool",
        "runner": "apps.my_tool.scanner.run_my_tool",
        "phase": 7,
        "phase_group": "Network Exposure",
        "requires": ["naabu"],          # tools that must run before yours
        "produces_findings": True,      # False = produces assets, not findings
    }
```

Then drop in `models.py` (empty), `collector.py` (run the binary / make
the probe), `analyzer.py` (parse results → build Finding or asset rows),
and `scanner.py` (thin orchestrator: `collect → analyze → save`). Add
`"apps.my_tool"` to `INSTALLED_APPS` in `openeasd/settings.py`. That's
it — the tool shows up in the workflow editor and runs in pipeline order.

Look at `apps/web_checker/` or `apps/ssh_checker/` for working examples
of the five-file pattern (`apps.py`, `models.py`, `collector.py`,
`analyzer.py`, `scanner.py` — plus the standard `__init__.py` Python
package marker). `apps/subfinder/` is a good asset-producing example
(`produces_findings: False`).

### Phase numbers

Phases are sequential integers 1–11 matching the pipeline order in `CLAUDE.md`. Pick the phase that correctly places your tool relative to its dependencies. Tools with the same phase number run in parallel. Do **not** use fractional phases (e.g. `3.5`) — use the next integer and renumber if needed.

The `requires` list is advisory — it documents which earlier-phase tools
your tool depends on (e.g. `["subfinder"]` if you read `Subdomain`
rows). Use the tool's `label` value from its `AppConfig`, not the app
path.

### Writing good findings

Every finding your tool emits should be actionable by a security
engineer who has never seen your tool before. Three things matter:

**Severity calibration**

| Severity | When to use |
|---|---|
| `critical` | Immediate exploitation possible with no preconditions (unauthenticated RCE, full data exposure) |
| `high` | High-impact, straightforward to exploit (subdomain takeover, valid CVE with public PoC, expired TLS) |
| `medium` | Meaningful risk but requires additional conditions (weak cipher suites, missing HSTS, DMARC not enforced) |
| `low` | Defence-in-depth issue, low direct exploitability (informational header leak, SPF ~all vs -all) |
| `info` | Observation only, no exploitability (banner version, open port with no known CVEs) |

When in doubt, go one severity lower rather than one higher — alert
fatigue from over-reported highs is worse than under-reporting a medium.

**Description**

Explain *why this is a problem* for this specific target. Avoid generic
CVE copy-paste. One or two sentences is enough:

```
# Good
"blog.example.com resolves to an unclaimed Heroku dyno. An attacker who
registers that dyno name can serve arbitrary content under your subdomain,
including credential phishing pages that inherit its TLS certificate."

# Too generic
"Subdomain takeover vulnerabilities allow attackers to take control of subdomains."
```

**Remediation**

Tell the operator exactly what to do, not just that something is wrong:

```
# Good
"Remove the CNAME record for blog.example.com or reclaim the Heroku dyno
at old-app.herokuapp.com. Verify by running: dig CNAME blog.example.com"

# Too vague
"Fix the subdomain configuration."
```

Store tool-specific data (CVE IDs, cipher names, service fingerprints,
raw tool output) in the `extra` JSONField — not in the description text.
This keeps the description human-readable and makes the raw data
queryable.

**Common field mistakes to avoid**

- `extra=` not `extras=` — the JSONField is named `extra` (no `s`)
- `port=` takes a `Port` FK instance, not an integer — use `port_number=` for the integer
- `url=` takes a `URL` FK instance from `apps.web_assets`

### Required tests for new tool PRs

Every tool app needs a `tests/unit/test_<tool>.py`. PRs without tests
will be asked to add them before merge. Cover at minimum:

**Collector**
- Empty input returns `[]`
- Binary not found (`shutil.which` returns `None`) returns `[]`
- Non-zero exit code returns `[]`
- Timeout returns `[]`
- Happy path: valid output returns parsed records

**Analyzer**
- Empty records returns `[]`
- Record that should not produce a finding (e.g. `vulnerable=False`) is skipped
- Happy path: correct finding fields (`source`, `check_type`, `severity`, `title`, `extra`)
- Deduplication works if your tool can emit duplicate records

**Scanner**
- No assets to scan returns `[]` without calling the binary
- Happy path: findings are persisted to DB and returned

Use `@pytest.mark.django_db` for tests that touch the database.
See `tests/unit/test_ssh_checker.py` (33 tests) or
`tests/unit/test_takeover_check.py` (35 tests) as reference.

## Other ways to help

- **Bug reports.** Open an issue using the "Bug report" template — exact
  reproducer + version (image tag or git SHA) + what you ran.
- **Feature requests.** Use the "Feature request" template. Tell us the
  problem first, the solution second.
- **Docs.** README/CHANGELOG/CLAUDE.md fixes are welcome PRs. Typo fixes
  go straight in; structural rewrites — open an issue first so we can
  agree on direction before you write.
- **Frontend tweaks.** React 19 + Vite 8 + Tailwind + shadcn/ui in
  `frontend/`. Run `npm run dev` against a Django backend on `:8000`.
- **Tests.** We're at ~760 tests excluding slow DNS; raising that
  number always helps. `tests/unit/test_<thing>.py` matches the app it
  tests.

## What to grep first (avoid re-discovery)

- `CLAUDE.md` — project conventions, architecture rules, gotchas. Read
  this before opening a non-trivial PR.
- `CHANGELOG.md` — explains *why* recent changes were made, not just what.
- `apps/core/workflows/registry.py` — the auto-registration plumbing.
- `apps/core/findings/models.py` — the unified Finding model every
  tool writes to.

## Development setup

```bash
# Install Python deps (uv handles the lockfile)
uv sync --group dev

# Install frontend deps
cd frontend && npm install && cd ..

# Run migrations
uv run manage.py migrate

# Terminal 1 — Django + Django-Q2 worker
uv run python main.py

# Terminal 2 — Vite dev server (proxies /api/ to Django on port 8000)
cd frontend && npm run dev
```

App runs at `http://localhost:5173` in dev. Default login on a fresh DB
is `admin` / `admin`, force-change-password kicks in.

External tools (`subfinder`, `dnsx`, `naabu`, `httpx`, `nuclei`,
`amass`, `nmap`) need to be on `PATH`. Easiest install is the
ProjectDiscovery `pdtm` (`pdtm -i subfinder,dnsx,naabu,httpx,nuclei`)
plus `brew install nmap` and `go install github.com/owasp-amass/amass/v4/...@master`.

## Tests before you push

```bash
# Fast suite (excludes slow real-network DNS tests)
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py
```

CI runs the same. PR will block if anything fails. If your change
touches a tool collector, add or update a unit test in
`tests/unit/test_<tool>.py`.

## Commit messages

Conventional Commits style. Examples from the recent history:

```
feat(api): accept session_uuid on /api/scans/findings/
fix(runner): findings_count no longer counts asset rows as findings
docs(security): add SECURITY.md + enable GitHub PVR
```

Body explains the *why*, not just the what — see existing commits for
the format. Ending with a Co-Authored-By line is welcome but not
required.

## Code style

- Python: follow what's there. We use Django 5+ idioms. No formatter
  enforced in CI yet; please don't reformat unrelated lines in your PR.
- JS: ES modules + JSX. Tailwind utility classes for styling.
- Comments: only when the *why* is non-obvious. Don't restate the code.
- Don't introduce new dependencies in a small PR — flag it in the
  description and we'll talk through it.

## Security issues

**Do not open a public issue for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the private reporting channel (GitHub
PVR preferred, `contact@cybersecify.com` as fallback).

## License

By contributing, you agree your contribution is licensed under the
[MIT License](LICENSE) — same as the rest of the project.

## Code of Conduct

Be reasonable. Don't be a jerk in issues, PRs, or discussions. We'll
adopt the Contributor Covenant 2.1 if anything needs formal arbitration
— for now, common sense.
