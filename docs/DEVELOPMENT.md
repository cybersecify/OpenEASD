# Local Development

How to run OpenEASD on your machine for development — the native `just dev` /
`make dev` loop (not Docker). For deployment see the README; for *what* to build
(adding a scan tool) see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## The mental model

Local dev runs **three processes side by side**, all talking to one PostgreSQL DB:

```
  Vite dev server  :5173   ← open this in the browser (React SPA)
      │  proxies /api/* ─┐
  Django runserver :8001 ←┘   REST API (Django Ninja); enqueues scans
  DBOS worker              executes scan / AI workflows off the DB queue
                    │
   all three ───────┴────►  PostgreSQL :5432  (app data + DBOS durable schema)
```

You browse **http://localhost:5173**; Vite forwards `/api/*` to Django on `:8001`
(so there's no CORS config). Scans only actually *execute* when the worker is up.

> The Docker stack (`just up`) is different — it serves everything on **:8000**.
> The `:5173` / `:8001` split is native-dev only.

## Prerequisites

| Need | Version | Notes |
|---|---|---|
| PostgreSQL | 17 | The app is Postgres-only (no SQLite). `brew services start postgresql@17` |
| Python (via [uv](https://docs.astral.sh/uv/)) | **3.12** | pinned in `.python-version`; `uv` installs it for you |
| Node | **20** | pinned in `.nvmrc` (`nvm use`); newer majors work too (`engines: >=20.19`) |
| Scanner binaries | — | subfinder, nmap, nuclei, … — only needed to run *active scans*, not for UI/API dev |

**macOS also needs** `brew install pango` (for WeasyPrint PDF reports) — see
[Troubleshooting](#troubleshooting).

## First-time setup

```bash
# 1. Create the database (defaults the app expects; override via .env)
createdb openeasd
createuser openeasd

# 2. Environment file
cp .env.example .env
#    Set SECRET_KEY and the DB_* block. Generate a key with:
#    uv run python -c "from django.core.management.utils import get_random_secret_key as k; print(k())"

# 3. Install deps + apply migrations + build frontend deps
make setup        # or: just setup
#    → uv sync --group dev      (Python env on 3.12)
#    → manage.py migrate        (needs Postgres running)
#    → cd frontend && npm install

# 4. Create your admin login (native dev has no auto-admin; that's Docker-only)
uv run manage.py createsuperuser   # or: just createsuperuser
```

## Daily loop — one command

```bash
make dev          # or: just dev
```

Launches all three processes together (Ctrl-C stops all):

- `npm run dev` → Vite on **:5173**
- `manage.py runserver 8001` → Django on **:8001**
- `manage.py dbos_worker` → the scan/AI worker

Then open **http://localhost:5173**, log in, add a domain, run a scan.

### Run pieces individually

```bash
just backend      # only Django  :8001
just worker       # only the DBOS worker (required for scans to execute)
just frontend     # one-off production bundle build
```

## Before you push — verify like CI

```bash
just ci           # ruff + pytest (80% coverage gate) + bandit + pip-audit + vitest + build
                  # mirrors .github/workflows/ci.yml exactly
```

Pieces, if you want them separately:

```bash
just lint         # ruff check apps/ openeasd/ tests/
just test         # fast pytest (excludes the slow real-network domain_security tests)
just test-all     # everything, including the slow DNS/RDAP tests
just ci-frontend  # vitest + production build
```

Fast backend suite directly (needs Postgres + `DB_*` in the environment):

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py
```

## Docker dev path (optional)

The three-container stack (db + web + worker), for testing the deployed shape:

```bash
just up           # build locally from source → http://localhost:8000
just deploy-dev   # pull the CI-published :latest GHCR images instead of building
just down         # stop (keeps the db volume)
just logs / just ps
```

> On Apple Silicon, `just up` builds native arm64 images. `just deploy-dev` pulls
> the published GHCR images, which are **amd64-only** — they'll run under emulation.

## Ship it — verify in dev, then promote to prod

The rule: **verify everything in dev; never debug on the live instance.** Prod
only ever receives an already-verified, tagged image.

**1 — Verify the code (native).** Build on a `feat/`/`fix/` branch with `just dev`,
click through the feature at http://localhost:5173, run a scan on an *authorized*
test domain, and confirm any new migrations apply (`uv run manage.py migrate`).
Then the go/no-go gate:

```bash
just ci           # green here = green in GitHub CI. Don't proceed on red.
```

**2 — Merge + release.** PR → CI green → squash-merge. Accumulate features in the
CHANGELOG `[Unreleased]` and cut **one** tagged release for the batch:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z    # GHCR builds :vX.Y.Z (web + worker)
```

**3 — Smoke-test the REAL image (closes the "native ≠ image" gap).** Before
touching prod, run the exact published artifact locally — this catches
image-only issues (a missing binary in the worker image, entrypoint/env,
migrations under the real image) that native dev can't:

```bash
OPENEASD_TAG=vX.Y.Z just deploy-dev     # pulls & runs ghcr.io/…:vX.Y.Z
# → http://localhost:8000 : login, run one scan, check the feature. Then `just down`.
```

**4 — Promote.** Bump the **single source of truth** — `newTag` in
`k8s/kustomization.yaml` — to the version you just smoke-tested, then apply:

```bash
# edit k8s/kustomization.yaml:  newTag: vX.Y.Z   (both web + worker)
kubectl apply -k k8s/
kubectl rollout restart deployment/openeasd-web deployment/openeasd-worker
```

**Rollback** is the same move in reverse: set `newTag` back to the previous
version and re-apply. Because tags are immutable, this is deterministic — the
`imagePullPolicy: IfNotPresent` deployments pull the new tag and cache it.

> The k8s Deployments use **bare image names**; the tag is set *only* by
> `kustomization.yaml` (`images[].newTag`). Bump it in one place to promote.

> ⚠️ **Migration-safe deploys: bump `newTag` + `apply -k` — do NOT `kubectl set
> image ...web=…`.** The web Deployment has **two** containers on the web image:
> an **`init` container that runs `migrate`** and the `web` container that runs
> gunicorn. `kubectl set image deploy/openeasd-web web=…:vX.Y.Z` updates *only*
> the `web` container — the `init` container keeps the **old** image, so on a
> release that adds a migration, `migrate` runs with the **old code** and the new
> migration is **silently skipped** (the app boots on the new version against a
> schema missing the new table/column). `kustomize` `newTag` rewrites the image
> for *every* container (init + web + worker) at once, so `apply -k` always
> migrates with the new code. If you must hot-patch with `set image` (a
> migration-less patch only), set the init container too:
> `kubectl set image deploy/openeasd-web init=…:vX.Y.Z web=…:vX.Y.Z`. After any
> deploy that includes a migration, verify it applied:
> `kubectl exec deploy/openeasd-web -c web -- python manage.py showmigrations`.

> ⚠️ **Drain scans before rolling the worker, or the queue can jam.** A worker
> rollout that lands **while scans are running** orphans the in-flight `run_scan`
> DBOS workflows: the new worker's code hash differs from the old one's, so it
> **cannot recover** them, and — because the `scans` queue is `concurrency=2` —
> a couple of stranded `PENDING` workflows **occupy both slots permanently** →
> every new scan sits `pending` forever (observed 2026-09-12; see the
> producer→queue→consumer hardening plan, **H8**). Safe rollout:
> 1. Quiesce new enqueues during the window: `SCHEDULED_SCANS_ENABLED=false`.
> 2. Wait for in-flight scans to finish (the Scans page, or check for
>    `running`/`pending` sessions) before rolling the worker.
> 3. After the rollout, clear any phantom slot-holders immediately:
>    `kubectl exec deploy/openeasd-web -c web -- python manage.py reap_orphan_scans`
>    (add `--dry-run` to preview). It cancels only `run_scan` workflows whose
>    `ScanSession` is already terminal, so it can never kill a live scan. The
>    `scheduled_watchdog` cron also runs this reaper automatically every cycle, so
>    a skipped drain self-heals within ~`SCAN_PENDING_TIMEOUT_MINUTES` + one
>    watchdog interval — the manual command just makes it instant.

## Where things live

| Concern | File |
|---|---|
| Task runner | `justfile` (primary) · `Makefile` (same core recipes) |
| Env config | `.env` (gitignored) ← template `.env.example` |
| Python / version | `pyproject.toml`, `.python-version` (3.12), `uv.lock` |
| Node / version | `frontend/package.json` (`engines`), `.nvmrc` (20) |
| DB / app settings | `openeasd/settings/base.py` (`DB_*` / `DATABASE_URL`) |
| Architecture | [`docs/DESIGN.md`](DESIGN.md) · decisions in [`docs/DECISIONS.md`](DECISIONS.md) |

## Troubleshooting

**PDF report export returns HTTP 500 (macOS).** WeasyPrint can't find the
Homebrew-installed pango/cairo/glib libs — macOS's loader doesn't search
`/opt/homebrew/lib`, and its SIP-protected shell strips `DYLD_*` at startup.
Install the libs (`brew install pango`) and set the fallback path **inside** the
process that serves reports:

```bash
DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib uv run manage.py runserver 8001
```

(Docker/Linux are unaffected — the libs are on the default path there.)

**Login fails with a 500 / `remaining connection slots are reserved`.** Postgres
ran out of connections, usually from orphaned `runserver` / `dbos_worker`
processes left behind across restarts. Kill the stragglers and relaunch:

```bash
pkill -f "manage.py runserver"; pkill -f "dbos_worker"; pkill -f "npm run dev"
just dev
```

**`Error: That port is already in use.`** A previous `just dev` didn't shut down.
Same fix — `pkill` the stragglers above, then restart.

**Scans stay "pending" forever.** The DBOS worker isn't running. Start it
(`just worker`) — `runserver` alone enqueues scans but never executes them.
