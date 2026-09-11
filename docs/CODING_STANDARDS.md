# OpenEASD — Coding Standards

These are the conventions the OpenEASD codebase already follows, written down so
new code (and new tools) stay consistent with the old. They are **descriptive,
not aspirational** — every rule here reflects a pattern that is already load-bearing
somewhere in the tree, usually enforced by a test.

This document complements, and never overrides:

1. [`CLAUDE.md`](../CLAUDE.md) — the authoritative project/architecture/flow rules.
2. [`docs/DESIGN.md`](DESIGN.md) — layers, tiers, pipeline, apps.
3. [`docs/DECISIONS.md`](DECISIONS.md) — *why* the architecture is the way it is.

Precedence on any conflict: the user's explicit instruction → CLAUDE.md → this file.

Tooling that enforces the mechanical parts: **ruff** (lint), **pytest** with an
80% coverage gate, **bandit** (SAST), **pip-audit** (CVEs). Run the whole gate
locally with `just ci` before opening a PR.

---

## 1. Layout & layering

- Code lives under `apps/`, split into **`apps/core/`** (infrastructure) and
  **`apps/<tool>/`** (the 28 registered scanner tools). Core is further grouped
  into `console/` (UI/API), `engine/` (scans/workflows/durable/scheduler), and
  `data/` (models). Django labels are unchanged — the nesting is organisational.
- **Tools never import from each other.** Shared data flows only through the DB
  models in `apps/core/data/` (`assets`, `web_assets`, `findings`,
  `asset_inventory`). If a tool needs a helper another tool also has (a DNS
  resolver, a TXT lookup), it keeps its **own inline copy** rather than importing
  — `domain_probe` and `asn_cluster` both do this deliberately, with a comment
  citing the rule. This keeps tools independently testable and the import graph
  acyclic.
- **Leaf-module discipline in the engine.** `apps/core/engine/durable/constants.py`
  and `client.py` import nothing from their own package, so the web process can
  enqueue work by name without importing `workflows.py` (which pulls in DBOS).
  Keep enqueue-only code separate from workflow-definition code.

---

## 2. Scanner tool apps

Every tool app has the same shape. A new tool that doesn't follow it is wrong
until proven otherwise.

### 2.1 Self-registration (`apps.py`)

```python
class MyToolConfig(AppConfig):
    name = "apps.my_tool"
    label = "my_tool"
    verbose_name = "My Tool"
    default_auto_field = "django.db.models.BigAutoField"   # set it — don't omit
    tool_meta = {
        "label": "my_tool",
        "runner": "apps.my_tool.scanner.run_my_tool",   # dotted path
        "phase": 7,                                       # execution order (int)
        "phase_group": "Network Exposure",                # display category (str)
        "requires": ["naabu"],                            # upstream tool labels
        "produces_findings": True,
        "active": True,                                   # see §7
    }
```

- The registry (`apps/core/engine/workflows/registry.py`) auto-discovers
  `tool_meta` at startup. **No core code is edited to add a tool** — but see the
  "definition of done" in CLAUDE.md (INSTALLED_APPS + Full Scan migration +
  README + CHANGELOG + website). Registering alone does not put a tool in a scan.
- **`phase` (execution order) and `phase_group` (display category) are two
  orthogonal axes.** A category can span multiple phases. Don't conflate them.
- **`active` defaults to `True` in the registry on purpose.** A missing flag must
  never let a scanner probe an unauthorized target (§7). A passive tool sets
  `active: False` and carries a comment justifying the classification.

### 2.2 The three-file split

| File | Responsibility | Touches the ORM? |
|---|---|---|
| `collector.py` | Runs the binary / HTTP / DNS call. Owns all I/O, timeouts, temp files. Returns raw parsed records (`list[dict]`). | **No** |
| `analyzer.py` | Pure transform: raw records → unsaved `Finding`/model instances. In-scope filtering, dedup, capping. | **No** |
| `scanner.py` | Thin orchestrator `run_<tool>(session)`: `collect()` → `analyze()` → `bulk_create(..., ignore_conflicts=True)` → re-query → return saved rows. Logs one summary line. | Yes |

- `models.py` stays **empty** for stateless tools; only tools with admin-config
  (naabu, subfinder, amass) define models.
- Import models **lazily inside functions** (`from .models import …` inside
  `collect()`) to avoid app-loading ordering issues.
- `domain_security` and `domain_probe` are the two accepted exceptions (collect +
  analyze + save inline in `scanner.py`) because their checks are many small
  heterogeneous probes. New tools follow the three-file split.

### 2.3 Findings

All tools write to the single unified `apps.core.data.findings.Finding`:

- Always set: `session`, `source` (= tool label), `check_type`, `severity`
  (`critical|high|medium|low|info`), `title`, `description`, `remediation`,
  `target`. Link asset FKs where relevant (`subdomain`/`ip_address`/`port`/`url`).
- **Tool-specific fields go in the `extra` JSONField** (`default=dict`), surfaced
  via read-only `@property` accessors that all guard `isinstance(self.extra, dict)`.
  Never add a tool-specific column to `Finding`.
- `source` / `check_type` are free `CharField`s with **no `choices`** — the tool
  registry is the single source of truth; `SOURCE_CHOICES` is derived from it.
- **Every `check_type` you emit must have a CWE mapping** in
  `apps/core/console/reports/views.py::_CWE_BY_CHECK`. A guard test
  (`test_reports.py::test_every_emitted_check_type_has_cwe_mapping`) greps all of
  `apps/` for `check_type="..."` literals and fails CI on an unmapped one.

### 2.4 Fail-graceful contract (non-negotiable)

A tool must **never raise out of its `run_<tool>` orchestrator** and must never
fail the whole scan. Specifically:

- Binary collectors raise the **typed** `ToolBinaryMissing` / `ToolTimeout` (from
  `apps.core.engine.workflows.exceptions`) on `FileNotFoundError` /
  `TimeoutExpired`. The runner catches these and records a failed step — the scan
  continues as a **labeled partial** (§5).
- A non-zero exit is logged (with `stderr[:500]`) but output is still parsed.
- Per-line JSON parse is wrapped: `try/except json.JSONDecodeError: continue` —
  a malformed line is skipped, never fatal.
- Passive / HTTP / DNS tools swallow "not present" errors and return `[]`/`None`.
  When you write a broad `except`, tag it `# noqa: BLE001` **and add a one-line
  reason comment** — this is the dominant convention; a bare `except Exception:`
  with no comment is a review finding.
- Temp files are always removed in a `finally:` block.
- Degrade per-unit, not per-scan: nmap skips a timed-out IP and continues, but
  raises `ToolTimeout` only if *every* target timed out (so a partial result is
  never mistaken for "clean").

### 2.5 External calls

- **Honest User-Agent**: from `getattr(settings, "OPENEASD_USER_AGENT",
  "OpenEASD/1.0")` — binary `-H` flag or the shared `_user_agent()` helper. A
  target should be able to allowlist us.
- **Everything is bounded**: explicit `timeout=`, per-target rate limits
  (`-rate`/`-c`), and per-scan caps (`MAX_CANDIDATES`, `SHODAN_MAX_IPS`,
  `NUCLEI_MAX_TARGETS`, …). **Truncation is always logged, never silent.**
- Timeouts and caps come from `getattr(settings, "…", default)` so deployments
  can override them.

### 2.6 Logging

- Module-level `logger = logging.getLogger(__name__)`.
- Every message is prefixed with a bracketed scope: `[my_tool:{session.id}]`,
  `[scan:{id}]`, `[workflow:{run.id}]`, `[watchdog]`, `[monitoring]`.
- `info` = lifecycle/summary; `warning` = degraded/stderr; `error` = missing
  binary; `debug` = skipped lines. Log failures with `exc_info=True`.

---

## 3. REST API (Django Ninja)

- Each module exposes `router = Router(auth=JWTAuth())` in its `api.py`; the
  central `apps/core/console/api/ninja.py` mounts it with
  `api.add_router("/prefix", router)`. **New endpoint = one decorated function;
  new module = one import + one `add_router` line.**
- Authenticate via the project wrapper `apps/core/console/api/auth.py::JWTAuth`
  (it also enforces the forced-password-change gate server-side) — never
  ninja-jwt's `JWTAuth` directly. Opt out of auth **explicitly** with `auth=None`
  (e.g. `/health/`, `/version/`). `request.auth` is the authenticated `User`.
- **Response format is flat JSON** (no envelope). List endpoints return the
  pagination shape `{results|findings, total, page, total_pages, has_next,
  has_previous}`. `201` creates return `Status(201, {...})`.
- **Errors**: `raise HttpError(code, "message")`; the central handler renders
  `{"error": {"code": <SYMBOL>, "message": ...}}`. Prefer `HttpError(404, …)`
  over `get_object_or_404` so the 404 body matches the envelope (see finding F6).
- Request/response bodies are `ninja.Schema` subclasses defined next to the
  endpoint.

### 3.1 Secrets over the API are write-only

- Credential / AI-config / notification endpoints return **presence booleans + a
  `db|env|none` source**, never the stored value.
- Write semantics are uniform: `None` = unchanged, `""` = clear (fall back to
  env), non-empty = set.
- DB-wins-over-env resolution is centralized in
  `apps/core/console/credentials/resolver.py::get_credential` — **tools read keys
  through the resolver, never `settings` directly.** The resolver never raises; a
  store hiccup falls back to env and logs a warning.

---

## 4. Durable execution & orchestration (DBOS)

- **DBOS is quarantined behind `apps/core/engine/durable/`.** Task bodies never
  `import dbos`; they're wrapped by `@durable_task(name, dedupe=...)`, which gives
  a uniform surface: `task(*args)` runs in-process (tests) and
  `task.delay(*args, dedupe_id=...)` durably enqueues. Multi-step work stays an
  explicit `@DBOS.workflow` with per-phase `@DBOS.step`s (the checkpoint unit).
- **A durable enqueue that must never double-run carries a stable
  `deduplication_id`** + `duplication_policy: "return-existing"` (e.g.
  `scan-{session_id}`). But **don't dedupe a re-runnable task**: `ai_triage`
  dropped its `triage-{id}` dedupe (F2) because return-existing returned the
  prior completed run and blocked legitimate manual re-triage — serialize
  concurrency at the caller instead. Match the work to the policy.
- **Idempotency**: setup steps use `get_or_create` /
  `bulk_create(ignore_conflicts=True)`. The alert dispatcher skips when a
  `status="sent"` Alert already exists, so a finalize replay can't double-notify.
  *New finalize-stage side effects must be made replay-safe the same way* —
  finding F1 flags where this is currently incomplete.
- **Pure-planner-then-DB-write**: `resolve_phase_groups` / `_group_tools_by_phase`
  compute the plan with no DB writes and are shared by both the synchronous and
  DBOS paths so both compute an identical plan. DB writes happen only in the
  step-execution functions.

---

## 5. Error handling philosophy: labeled partials, never fake-complete

- A per-tool failure is caught, recorded as a failed `WorkflowStepResult`, and
  the run continues.
- Run outcome is **derived**: any failed step ⇒ `partial`; an unhandled exception
  ⇒ `failed`; otherwise `completed`. Session status mirrors the run — a
  half-finished scan is `partial`, so **zero findings is never silently read as
  "clean."**
- Fail-graceful side effects (asset rollup, AI hooks) are wrapped so they can
  never change a scan's outcome, with an explicit comment saying so.
- **Cancellation is cooperative**: `/stop` flips the session to `cancelled` in the
  DB; the runner re-reads status between phase groups and marks the rest
  `skipped` (a running phase finishes first). Finalize is skipped for cancelled
  sessions.

---

## 6. Data models

- **Session-snapshot vs persistent-inventory split**: per-scan
  `Subdomain`/`IPAddress`/`Port`/`URL` rows are `session`-scoped (CASCADE off the
  session); `asset_inventory.Asset` is the derived cross-scan layer, populated
  **only** by the finalize rollup — never by scanner tools.
- **FK cascade rule**: deleting a `Domain` wipes all its data (CASCADE chains).
  Links that must **outlive** their referent use `SET_NULL` **paired with an
  immutable identity copy** so the audit trail survives deletion — e.g.
  `Finding.asset` (SET_NULL) + `finding_key`; `AIInvocation.session` (SET_NULL) +
  `session_uuid`.
- **Singletons** use `pk=1` + a classmethod `get()` over `get_or_create(pk=1)`
  (`ToolCredentials`, `NotificationConfig`, `AISettings`).
- Index hot filter columns (`db_index=True` on source/check_type/severity/status;
  composite `Meta.indexes`). Natural-key uniqueness via `UniqueConstraint` /
  `unique_together`.
- **Aggregation note**: the codebase groups JSON-extracted fields in Python
  rather than DB-side `Max(...)` — a portability habit from the former SQLite
  backend. It's intentional; don't "fix" it. (But watch volume — finding F8.)

---

## 7. Security & authorization

### 7.1 The passive/active boundary

- **Active** (`active=True`): sends packets to the target → **requires a
  `DomainAuthorization`**. **Passive** (`active=False`): public / third-party data
  only → needs none.
- `is_passive_tool_set` is **conservative**: an empty set is *not* passive, an
  unknown tool defaults to active, and one active tool makes the whole set active.
- The gate lives in `apps/core/engine/scans/api.py`: only an immediate
  (`schedule_type="now"`) **all-passive** scan bypasses authorization. Every
  scheduled scan and any active tool keeps the gate. The scheduler and the AI
  agent (`guard.gate_subscan_tools`) **re-check authorization at execution time**
  — a revoked authorization can never scan. All three sites resolve authorization
  through the single `DomainAuthorization.is_authorized(domain)` classmethod (F3).

### 7.2 Secrets at rest

- Any secret stored in the DB uses `EncryptedCharField` / `EncryptedTextField`
  (`apps/core/fields.py`) — transparent Fernet encrypt-on-write / decrypt-on-read,
  backed by a TEXT column. Legacy plaintext decrypts tolerantly and re-encrypts on
  next save.
- **Fernet is non-deterministic → encrypted fields can never be used in `.filter()`
  equality lookups.** Read them only via singleton `.get()` + attribute access.
- Encrypted: BYOK keys, webhook URLs, the Cloudflare token. **Env-only / not
  encrypted**: bootstrap secrets (`SECRET_KEY`, `FIELD_ENCRYPTION_KEY`, `DB_*` —
  they bootstrap the crypto/DB) and non-secret identifiers (account IDs, Censys
  IDs).
- The `AIInvocation` audit model has **no TextField by design** — prompt/response
  bodies are structurally impossible to persist. A guard test greps for this.

### 7.3 Settings

- Every tunable goes through `config("NAME", default=..., cast=...)` with a safe
  default; `DATABASE_URL` wins over `DB_*` parts.
- **Fail-fast**: `_validate_secret_key` raises `ImproperlyConfigured` when
  `DEBUG=False` and the key still starts with `django-insecure` (the same key
  signs JWTs).
- Settings helpers (`_security_settings`, `_resolve_profile`) are **pure and
  return values**, then `globals().update(...)` — don't mutate settings globals
  inline.

---

## 8. Tests

- **pytest + pytest-django.** One module per app/area; tests grouped in `TestXxx`
  classes mirroring the unit under test. `@pytest.mark.django_db` on the class
  (`transactional_db` for concurrency/threading tests).
- Shared fixtures live in `tests/conftest.py` (`user`, `auth_client`, `domain`,
  `scan_session`, `completed_session`, …). **Use them — don't redefine local
  shadows** (finding F9). Import models lazily inside fixtures.
- **Mock externals at the module-local import site**, never globally: patch
  `apps.typosquat.collector.requests.get`, `apps.*.scanner.collect`,
  `apps.core.console.reports.views._render_pdf`, etc. PDF tests mock `_render_pdf`
  and assert on the captured HTML — no WeasyPrint native libs needed.
- **Assert behavior, not rendered markup.** Exact HTML strings / CSS classes /
  verbatim copy are brittle (finding F11). Assert the fact, not the template.
- **Guard / invariant tests are a required category** — they're what keep the
  registry, the scan, the report, and the docs from drifting:
  - every registered non-core tool is in Full Scan
    (`test_default_workflow.py`);
  - every tool has an `active` flag; the Passive Scan workflow has zero active
    tools (`test_passive_scan.py`);
  - every emitted `check_type` has a CWE mapping (`test_reports.py`);
  - every protected endpoint returns 401 unauthenticated (`test_api_endpoints.py`).
  **When you add a drift risk, add a guard test for it.**
- **Fast-vs-slow split**: `test_domain_security.py` makes real network calls and
  is excluded from fast CI via `--ignore=`. (This is currently a hardcoded path,
  not a marker — finding F10; prefer a `@pytest.mark.network` marker when you
  touch it.)

---

## 9. Frontend (React SPA)

- **Data layer**: `@tanstack/react-query` `useQuery` keyed by the API path
  (`queryKey: ['/scans/', domain, status, page]`). Single `QueryClient`
  (`staleTime: 0`, `retry: false`).
- **All HTTP goes through `api/client.js` `apiGet`/`apiPost`** over one axios
  instance (`baseURL: '/api'`). **Same-origin, no CORS** ever (Vite proxy in dev,
  WhiteNoise in prod). Don't reintroduce ad-hoc `fetch` (finding F12 flags the two
  existing offenders).
- Axios interceptors handle auth: request injects `Bearer` from
  `auth.getToken()`; response does single-flight 401→refresh, else `auth.clear()`
  + redirect to `/login`.
- `auth.js` is the **sole owner of `localStorage`** token keys.
- **Routing**: `createBrowserRouter` tree in `router.jsx`; everything private is
  nested under `<ProtectedRoute>`. Navigate with `useNavigate`, not a hand-rolled
  router.
- **UI**: shadcn/ui primitives (`components/ui/*`), Tailwind, dark-theme tokens
  (`bg-canvas`, `bg-card`, `border-rim`, `text-lit`, `text-dim`). Toasts via
  `components/Notification.jsx`.
- Tests: Vitest + Testing Library, co-located `*.test.{js,jsx}`.

---

## 10. Git & release flow

See CLAUDE.md for the authoritative rules. In short: **never commit to `main`**;
branch `feat/` (features) or `fix/` (everything else — bugs, deps, config, docs,
cleanup); commit-message prefix is the most specific of
`feat|fix|docs|ci|chore|test`; squash-merge + delete branch; tag `main` at
milestones with semver. Run `just ci` before every PR.

---

## Appendix: open review findings

Grounded in a full-tree review (2026-09-11). Ordered by priority. These are the
deltas between this document and the current code — fix-forward candidates, not
blockers. Fixed items are struck through with the PR that closed them.

### High — correctness / security

- **F1 — ~~finalize is not replay-idempotent except for alerts~~ — FIXED (#444).**
  `_detect_deltas` and `_check_coverage_regression` now delete-then-insert, and
  `_count_all_findings` excludes the `scan_coverage` meta-warning, so a finalize
  replay duplicates nothing and `total_findings` stays stable. `build_insights`
  (`update_or_create` + prune) and the asset rollup (`get_or_create`) were
  verified already replay-safe.
- **F1b — ~~within-group tool execution is not idempotent~~ — FIXED (#455).**
  `_run_single_step` is now idempotent on `(run, tool)`: on a crash-resume (the
  phase-group DBOS step re-runs the whole group) a tool that already reached a
  terminal state is skipped, and a non-terminal ("running"/"pending") row is
  reused instead of duplicated. `run_one_phase_group` also skips already-terminal
  tools up front so they aren't re-dispatched. Within-group execution now resumes
  cleanly, not just at the group boundary.
- **F7 — ~~notification config GET returns raw webhook URLs~~ — FIXED (#445).**
  `_serialize_config` now returns presence booleans + a `db|env|none` source per
  channel and never the URL; `save_config` adopts the None=unchanged /
  ""=clear / value=set write semantics so the threshold can be saved without
  wiping a stored webhook the UI can no longer read back. Matches
  `/api/credentials/` and `/api/ai/config/`.
- **F-sec1 — weak default DB credentials ship silently.** `DB_PASSWORD` defaults
  to `"openeasd"` with no fail-fast guard (unlike `SECRET_KEY`).
  (`openeasd/settings/base.py:210`)
- **F-sec2 — ~~SECRET_KEY guard skipped whenever `"pytest" in sys.modules`~~ —
  FIXED (#452).** Both the SECRET_KEY and DB-password guards now skip only under
  the pytest *runner* — a new `_under_pytest()` checks the process entrypoint
  (`sys.argv[0]` basename), not mere importability — so a transitive import of
  pytest in a production process (a dependency, a debug shell) can no longer
  disable a security guard. A subprocess regression test imports pytest *then*
  settings with an insecure key + `DEBUG=False` and asserts it still aborts.
- **F-sec3 — ~~`?token=<JWT>` query-param auth on report endpoints~~ — FIXED
  (#451).** Removed the query-param fallback in `_report_auth_required`; report
  endpoints now authenticate only via Django session or the `Authorization:
  Bearer` header (both SPA report pages already send the header via fetch+Blob,
  so nothing depended on it). A token in the query string is now ignored.

### Medium — consistency / robustness

- **F2 — ~~`ai_triage` dedupe key blocks manual re-triage~~ — FIXED (#454).**
  Dropped the `triage-{0}` dedupe (it returned the prior *completed* workflow via
  return-existing, so a re-run silently no-op'd while the UI sat at "running").
  Each manual run now enqueues a fresh workflow — matching `agent_step`, which
  carries no dedupe — and the concurrency the dedupe incidentally provided moved
  into the API as an atomic `select_for_update` in-flight guard (`run_triage_now`).
- **F3 — ~~the passive/active auth rule is implemented three times~~ — FIXED
  (#453).** The triplicated authorization check (`DomainAuthorization.objects
  .filter(domain__name=X).exists()` in the scan-start gate, subscan gate, and AI
  `gate_subscan_tools`) is now a single `DomainAuthorization.is_authorized(domain)`
  classmethod — one source of truth for a security gate, so a future change
  (e.g. authorization expiry) lands in one place. The passive-set predicate was
  already shared (`is_passive_tool_set`).
- **F4 — `_count_all_findings` returns 0 on any DB error** → a transient failure
  reports "0 findings" into `total_findings` and the reaper, reading as "clean."
  (`pipeline.py:159`)
- **F5 — uncommented `except: pass` blocks** swallow failures in the status
  endpoint (`scans/api.py:588`), scheduled-list (`:681`), and apex-seed DNS
  (`pipeline.py:377`). Add `# noqa: BLE001` + a reason, or log.
- **F6 — ~~two 404 body shapes~~ — FIXED (#456).** Added a Ninja `Http404`
  exception handler so a `get_object_or_404` miss renders the standard
  `{"error":{"code":"NOT_FOUND",…}}` envelope instead of Ninja's default
  `{"detail":"Not Found"}`. One handler covers every current and future
  `get_object_or_404` call site — no per-endpoint rewrites.
- **F-tool1 — ~~`domain_security`/`domain_probe` orchestrators have no top-level
  try/except~~ — FIXED (#448).** Both now wrap collect+analyze in
  `try/except → return []`, matching their passive Domain-Posture siblings
  (`breach_check`/`hudson_rock`/`dns_history`). `cloud_assets` is **not** wrapped:
  it's a binary tool and follows the binary-tool contract instead (propagate →
  "partial", like its sibling `takeover_check`) — resolved in F-tool3 below.
- **F-tool2 — ~~configured `_DNS_TIMEOUT` honored in only one check~~ — FIXED
  (#450).** Added `lifetime=_DNS_TIMEOUT` to all six `dns.resolver.resolve` calls
  in `domain_security` (was applied only to the lame-delegation `dns.query.udp`);
  a slow/hung authoritative server can no longer stall a scan past the configured
  bound. The two DNSSEC test mocks bound to `scanner.dns.resolver.resolve` now
  take `**kwargs` to tolerate the new arg.
- **F-tool3 — ~~`cloud_assets` skips on missing binary~~ — FIXED (#449).**
  Dropped the upfront `shutil.which → []` silent skip; a missing/timed-out
  `cloud_enum` now raises `ToolBinaryMissing`/`ToolTimeout` and propagates (the
  scanner has no swallowing wrapper), so the runner marks the scan "partial"
  instead of a fake "clean". **Ruling:** binary tools propagate, matching
  `takeover_check` — this also restores the intent of the earlier "tool failures
  no longer hidden behind `completed`" change, which had listed `cloud_assets`
  among the raisers.
- **F-tool4 — ~~`web_checker` hardcodes its own User-Agent~~ — FIXED (#448).**
  Now uses `settings.OPENEASD_USER_AGENT`, the shared honest UA.
- **F9 — local fixtures shadow `conftest.py`** in `test_api_endpoints.py` and
  `test_reports.py`; the two `auth_client`s differ subtly and can drift.
- **F11 — brittle report tests** assert exact HTML/CSS/copy strings rather than
  behavior (`test_reports.py`).
- **F12 — two frontend pages use ad-hoc `fetch()`** (`ReportsPage.jsx:26`,
  `ScanDetailPage.jsx:29`) bypassing the axios 401-refresh interceptor, with a
  near-duplicated `downloadReport` helper. Route through the client.

### Low — hygiene / drift

- **F-sec4 — no HTTPS-by-default**: `SECURE_SSL_REDIRECT`/`SECURE_HSTS_SECONDS`
  default off even when `DEBUG=False` (documented trade-off; enable via env behind
  TLS).
- **F-sec5 — `LOGIN_RATELIMIT_TRUST_FORWARDED_FOR=True` default** is a foot-gun if
  ever deployed without a header-stripping proxy (documented).
- **F-bug1 — dead `github_secret` credential mapping**: `FIELD_BY_SETTING` points
  at a non-existent `GITHUB_SECRET` setting, so its env fallback is dead.
  (`credentials/models.py:24`)
- **F8 — Python-side full-table aggregation** in `_detect_deltas` /
  `_compute_coverage` is fine now but should move DB-side as finding volume grows.
- **F-dup — severity orderings defined 4× independently** (`SEVERITY_LEVELS`,
  `SEVERITY_RANK`, `_SEVERITY_ORDER`, `_SEV_RANK`) and the
  `source:check_type:title` identity key is built inline in three places.
  Consolidate into shared helpers.
- **F-misc — stale comments / config drift**: `nuclei` timeout comments say
  "30m→2h" but the value is 6h; `asn_cluster` comment says "Prioritization" but
  `phase_group="Brand Threat"`; ~~several tool `apps.py` omit
  `default_auto_field`~~ (FIXED #448 — the 6 that omitted it now set it);
  `Badge.jsx` lists status keys twice; `axiosInstance.js` imports `router.jsx`
  (near-circular — prefer a navigation callback).
