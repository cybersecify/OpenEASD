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
