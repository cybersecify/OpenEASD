# OpenEASD — Operations Runbook

How to run OpenEASD on your machine for development — the native `just dev` /
`make dev` loop (not Docker). For deployment see the README; for *what* to build
(adding a scan tool) see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## The mental model

Local dev runs **two processes side by side**, both talking to one PostgreSQL DB:

```
  Django runserver :8001   ← open this in the browser (server-rendered plain-Django UI)
                    │         serves the UI AND enqueues scans (no REST API, no SPA)
  DBOS worker               executes scan / AI workflows off the DB queue
                    │
   both ────────────┴────►  PostgreSQL :5432  (app data + DBOS durable schema)
```

You browse **http://localhost:8001** directly — the UI is server-rendered Django
(`apps/mvp`, session auth); there is no separate frontend server and no `/api/`.
Scans only actually *execute* when the worker is up.

> The Docker stack (`just up`) serves everything on **:8000**; native dev is on **:8001**.

## Prerequisites

| Need | Version | Notes |
|---|---|---|
| PostgreSQL | 17 | The app is Postgres-only (no SQLite). `brew services start postgresql@17` |
| Python (via [uv](https://docs.astral.sh/uv/)) | **3.12** | pinned in `.python-version`; `uv` installs it for you |
| Scanner binaries | — | subfinder, nmap, nuclei, … — only needed to run *active scans*, not for UI dev |

(No Node / frontend toolchain — the UI is server-rendered Django with vendored
Bulma + HTMX, no build step.)

## First-time setup

```bash
# 1. Create the database (defaults the app expects; override via .env)
createdb openeasd
createuser openeasd

# 2. Environment file
cp .env.example .env
#    Set SECRET_KEY and the DB_* block. Generate a key with:
#    uv run python -c "from django.core.management.utils import get_random_secret_key as k; print(k())"

# 3. Install deps + apply migrations (the UI is server-rendered — no frontend build)
make setup        # or: just setup
#    → uv sync --group dev      (Python env on 3.12)
#    → manage.py migrate        (needs Postgres running)

# 4. Create your admin login (native dev has no auto-admin; that's Docker-only)
uv run manage.py createsuperuser   # or: just createsuperuser
```

## Daily loop — one command

```bash
make dev          # or: just dev
```

Launches both processes together (Ctrl-C stops all):

- `manage.py runserver 8001` → Django on **:8001** (serves the UI)
- `manage.py dbos_worker` → the scan/AI worker

Then open **http://localhost:8001**, log in, add a domain, run a scan.

### Run pieces individually

```bash
just backend      # only Django  :8001
just worker       # only the DBOS worker (required for scans to execute)
```

## Before you push — verify like CI

```bash
just ci           # ruff + pytest (80% coverage gate) + bandit + pip-audit
                  # mirrors .github/workflows/ci.yml exactly
```

Pieces, if you want them separately:

```bash
just lint         # ruff check apps/ openeasd/ tests/
just test         # fast pytest (excludes the slow real-network domain_security tests)
just test-all     # everything, including the slow DNS/RDAP tests
```

Fast backend suite directly (needs Postgres + `DB_*` in the environment):

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py
```

## Docker dev path (optional)

The three-container stack (db + web + worker), for testing the deployed shape:

```bash
just up           # build the 3-tier stack locally from source → http://localhost:8000
just down         # stop (keeps the db volume)
just logs / just ps
```

> The **single image** is the only image published to GHCR
> (`ghcr.io/cybersecify/openeasd`). The 3-tier `web`/`worker` images are **not**
> published — `just up` builds them locally from the Dockerfile `web`/`worker`
> targets. To test the single-image shape instead:
> `docker compose -f docker-compose.singleimage.yml up -d --build` (also `:8000`).
> On Apple Silicon these build native arm64; the published single image is amd64-only
> and runs under emulation.

## Ship it — verify in dev, then promote to prod

The rule: **verify everything in dev; never debug on the live instance.** Prod
only ever receives an already-verified, tagged image.

**1 — Verify the code (native).** Build on a `feat/`/`fix/` branch with `just dev`,
click through the feature at http://localhost:8001, run a scan on an *authorized*
test domain, and confirm any new migrations apply (`uv run manage.py migrate`).
Then the go/no-go gate:

```bash
just ci           # green here = green in GitHub CI. Don't proceed on red.
```

**2 — Merge + release.** PR → CI green → squash-merge. Accumulate features in the
CHANGELOG `[Unreleased]` and cut **one** tagged release for the batch:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z    # GHCR builds the single image :vX.Y.Z
```

**3 — Smoke-test the REAL image (closes the "native ≠ image" gap).** Before
touching prod, run the exact published artifact locally — this catches
image-only issues (a missing binary in the worker image, entrypoint/env,
migrations under the real image) that native dev can't:

```bash
# docker-compose.singleimage.yml builds locally by default; point it at the published tag:
docker run --rm -p 8000:8000 -v openeasd-smoke:/data \
  -e SECRET_KEY=$(openssl rand -hex 32) -e DB_PASSWORD=smoke -e DEBUG=False \
  -e ALLOWED_HOSTS=localhost ghcr.io/cybersecify/openeasd:vX.Y.Z
# → http://localhost:8000 : login, run one scan, check the feature. Then stop + `docker volume rm openeasd-smoke`.
```

**4 — Promote.** Bump the **single source of truth** — `newTag` in
`k8s/kustomization.yaml` — to the version you just smoke-tested, then apply:

```bash
# edit k8s/kustomization.yaml:  newTag: vX.Y.Z
kubectl apply -k k8s/          # Recreate strategy → the pod is replaced (short downtime)
```

**Rollback** is the same move in reverse: set `newTag` back to the previous
version and re-apply. Because tags are immutable, this is deterministic — the
`imagePullPolicy: IfNotPresent` deployment pulls the new tag and caches it.

> The k8s Deployment uses the **bare image name**; the tag is set *only* by
> `kustomization.yaml` (`images[].newTag`). Bump it in one place to promote.
> `kubectl set image` works too (one container, no init container — the
> single-image entrypoint runs `migrate` itself on every start), but `apply -k`
> keeps git as the source of truth for what prod runs. After any deploy that
> includes a migration, verify it applied:
> `kubectl exec deploy/openeasd -- python manage.py showmigrations`.

> **Single pod, single writer.** The embedded Postgres lives on a ReadWriteOnce
> PVC, so the Deployment is pinned to `replicas: 1` with `strategy: Recreate` —
> never scale it, and expect a short downtime per update. Back up the PVC
> (volume snapshot or `kubectl exec deploy/openeasd -- pg_dump -U openeasd openeasd`).

> ⚠️ **Drain scans before rolling the pod, or the queue can jam.** A rollout
> that lands **while scans are running** orphans the in-flight `run_scan`
> DBOS workflows: the new worker's code hash differs from the old one's, so it
> **cannot recover** them, and — because the `scans` queue is `concurrency=2` —
> a couple of stranded `PENDING` workflows **occupy both slots permanently** →
> every new scan sits `pending` forever (observed 2026-09-12; see the
> producer→queue→consumer hardening plan, **H8**). Safe rollout:
> 1. Quiesce new enqueues during the window: `SCHEDULED_SCANS_ENABLED=false`.
> 2. Wait for in-flight scans to finish (the Scans page, or check for
>    `running`/`pending` sessions) before rolling the pod.
> 3. After the rollout, clear any phantom slot-holders immediately:
>    `kubectl exec deploy/openeasd -- python manage.py reap_orphan_scans`
>    (add `--dry-run` to preview). It cancels only `run_scan` workflows whose
>    `ScanSession` is already terminal, so it can never kill a live scan. The
>    `scheduled_watchdog` cron also runs this reaper automatically every cycle, so
>    a skipped drain self-heals within ~`SCAN_PENDING_TIMEOUT_MINUTES` + one
>    watchdog interval — the manual command just makes it instant.

## Single-image deployment (one container)

One image (`target: singleimage`) runs embedded PostgreSQL + gunicorn + the DBOS
worker under honcho and serves the UI at `/` on port 8000. This is also what the
`k8s/` manifests deploy (one pod + a `/data` PVC). The privilege-separated 3-tier
compose path (external Postgres, separate web + worker) remains the option for
multi-host or scaled deployments.

```bash
docker buildx build --target singleimage -t openeasd:singleimage .

docker run -d --name openeasd -p 8000:8000 -v openeasd-data:/data \
  -e SECRET_KEY=<a long random secret> \
  -e DB_PASSWORD=<a strong db password> \
  -e DEBUG=False \
  -e ALLOWED_HOSTS=<your host,localhost> \
  openeasd:singleimage
```

Or: `docker compose -f docker-compose.singleimage.yml up -d --build` (reads `.env`).

> **The `/data` volume is MANDATORY.** It holds the Postgres cluster
> (`/data/pgdata`). Without it, all scan history is lost when the container is
> replaced.

| Env | Required | Notes |
|---|---|---|
| `SECRET_KEY` | yes | Boot guard refuses the insecure default |
| `DB_PASSWORD` | yes | Boot guard refuses `openeasd` |
| `ALLOWED_HOSTS` | yes | Comma-separated hosts |
| `DEBUG` | yes | Must be `False` |
| `DB_NAME` / `DB_USER` | no | Default `openeasd` |
| `DB_PORT` | no | Default `5432` |
| `SCHEDULED_SCANS_ENABLED` | no | Default `True`; `False` = manual-only |
| `OPENEASD_PROFILE` | no | `auto`/`low`/`balanced`/`high` |

- **First login:** `admin` / `admin`, forced through a password change.
- **Startup** takes ~20-50s cold (initdb, migrate, collectstatic, admin, honcho).
- **Active scans** (nmap/naabu raw sockets) need `--cap-add=NET_RAW` on `docker run`
  (set in the compose file); passive scans do not.
- **HTTPS:** put a TLS-terminating reverse proxy (Caddy/nginx/Cloudflare) in front
  of :8000. Never expose bare HTTP with real credentials.
- **Backup** (logical dump of the embedded database):

```bash
docker exec openeasd sh -lc 'PGBIN=$(ls -d /usr/lib/postgresql/*/bin); su postgres -c "$PGBIN/pg_dump -p 5432 openeasd"' > backup.sql
```

## Sizing (RAM / CPU / disk)

The binding constraint is **RAM during active scans** — `nuclei` parses ~13,500
templates into memory (~500 MB fixed) and `amass` brute-forces; passive-only scans
(DNS/RDAP/Shodan/API lookups) are light. `OPENEASD_PROFILE` auto-detects from host
RAM (`low` <2 GB · `balanced` 2–8 GB · `high` ≥8 GB) and tunes nuclei `-bulk-size`,
`GOMEMLIMIT`, tool concurrency, and amass-brute accordingly; force it with the env
var if auto-detection is wrong. **Add swap on a 1 GB box.**

| Workload | RAM | CPU | Disk |
|---|---|---|---|
| **Floor** (passive-only, or `low` profile + swap) | 1 GB + swap | 1 core | ~2 GB image + 10 GB `/data` volume |
| **Recommended** (Full Scan / active — the single-image default) | **4 GB** | 2 cores | ~2 GB image + 10–20 GB `/data` |
| **Heavy / concurrent scans** | 8 GB+ | 4 cores | 20 GB+ (consider the 3-tier deploy to scale the worker) |

Notes specific to the **single image** (embedded Postgres + web + worker):
- The embedded PostgreSQL adds roughly **150–300 MB RAM** on top of the engine floor;
  the k8s pod is sized to a **4 Gi** limit after an OOM incident under concurrent
  Passive·Deep load — mirror that if you cap the container (`docker run --memory=4g`).
- The image is **~2 GB on disk** (full scanner matrix + baked nuclei templates).
- The **`/data` volume is mandatory** and grows with scan history — start at **10 GB**.
- **Outbound internet** is required (targets + third-party APIs: Shodan, RDAP, HIBP,
  GitHub). **`--cap-add=NET_RAW`** is needed only for active scans (nmap/naabu raw
  sockets); passive scans don't need it.
- Under-provisioning doesn't error loudly — the kernel OOM-kills nuclei/amass mid-scan,
  yielding silent **partial** results. If scans come back thin on a small box, raise RAM
  or set `OPENEASD_PROFILE=low` (+ swap).

## Where things live

| Concern | File |
|---|---|
| Task runner | `justfile` (primary) · `Makefile` (same core recipes) |
| Env config | `.env` (gitignored) ← template `.env.example` |
| Python / version | `pyproject.toml`, `.python-version` (3.12), `uv.lock` |
| DB / app settings | `openeasd/settings/base.py` (`DB_*` / `DATABASE_URL`) |
| Architecture | [`docs/03-system.md`](03-system.md) · decisions in [`docs/DECISIONS.md`](DECISIONS.md) |

## Troubleshooting

**Login fails with a 500 / `remaining connection slots are reserved`.** Postgres
ran out of connections, usually from orphaned `runserver` / `dbos_worker`
processes left behind across restarts. Kill the stragglers and relaunch:

```bash
pkill -f "manage.py runserver"; pkill -f "dbos_worker"
just dev
```

**`Error: That port is already in use.`** A previous `just dev` didn't shut down.
Same fix — `pkill` the stragglers above, then restart.

**Scans stay "pending" forever.** The DBOS worker isn't running. Start it
(`just worker`) — `runserver` alone enqueues scans but never executes them.


---

## Scan Operational Learnings

Problems hit running **real** scans, their root cause, the fix, and the
regression test that now guards each one. Rule: every operational failure we see
in production becomes a documented learning **and** a test, so it can't silently
recur. Add to this list whenever a scan misbehaves.

### nuclei (the biggest source of pain)

**Key correction (verified against ProjectDiscovery maintainers):** nuclei parses
**all** ~13,500 templates into RAM up front (~500 MB, fixed) and *then* applies
`-severity`/`-tags` filters. So severity scoping does **NOT** shrink the startup
parse — it only cuts the *executed* set. The startup parse (~500 MB) on top of
the DBOS worker + Django is what tips a 1 GB box; runtime peak is
`concurrency × bulk-size × per-host buffer`. The levers that actually prevent the
**freeze** are `GOMEMLIMIT` + a small **`-bulk-size`**, not `-severity`.

| Symptom | Root cause | Fix | Guard |
|---|---|---|---|
| **Freeze** (box + web UI unresponsive for minutes) | ~500 MB startup template parse + runtime `c × bulk-size × per-host buffer` on a 1 GB host | `GOMEMLIMIT` soft heap cap **+** small `-bulk-size` per profile (low=5) — NOT `-severity` | `test_nuclei.py::test_go_memory_limit_applied_to_subprocess`, `::test_cmd_includes_memory_and_scope_flags`; `test_settings_security.py::test_bulk_size_scales_down_on_low_profile` |
| **Timeout** (wall hit, findings discarded) | Template *execution*: targets × executed templates ÷ polite rate | Give nuclei TIME to finish (6h `NUCLEI_TIMEOUT`, 24h worker/watchdog) rather than capping its output; `-type http` + `-max-host-error` trim wasted work. AND if the wall still hits, **deliver the partial findings** nuclei already wrote (`run_capped` carries them on `TimeoutExpired.output`; both collectors parse + return them) instead of discarding them for a false 0 | `test_nuclei.py::test_timeout_delivers_partial_findings`, `test_nuclei_network.py::test_collect_timeout_delivers_partial_findings`, `::test_cmd_includes_memory_and_scope_flags` |
| **Low value / noise** | `info` tech-detect templates are already covered by httpx `-tech-detect` + web_checker; they bury real findings | Scope to `critical,high,medium(,low)` per profile (`NUCLEI_SEVERITY`). NOTE: this also drops the unique `exposures` bucket (.git/.env/backups/tokens) — a value gap; re-including it needs a memory-safe second pass (`-include-tags` does NOT override `-severity` on v3.2.9, verified) — deferred | `test_settings_security.py::TestResourceProfile` |
| **Wedge / lost findings** | `nuclei_network` used plain `subprocess.run` (no process-group kill) → an escaped interactsh helper could hold the pipe and hang the worker | Both nuclei collectors now use the shared `run_capped` (temp-file redirect + `killpg`) | `test_nuclei.py::TestRunProcessGroupKill` |
| **Empty output** | The target **dropped the scanner's probes** → httpx returned 0 live URLs → nuclei had nothing to scan | Coverage/blocking problem, not nuclei — surfaced by the coverage-regression finding + `partial` status | `test_coverage_regression.py` |

**Template freshness:** templates are baked into the image and
`-disable-update-check` is set (a mid-scan template download once wedged a scan
for hours). Consequence: templates are frozen at image-build time and **rot** —
an old image misses new CVEs. A **weekly CI cron** now rebuilds `:latest` so
templates refresh on cadence (`.github/workflows/ci.yml`). Do **not** re-enable
runtime template updates.

**Deferred nuclei follow-ups:** (a) re-include the `exposures` template bucket
via a memory-safe mechanism; (b) store `info.tags` / `classification.cwe-id` for
richer report categorisation. (Recovering partial findings on a wall-timeout —
formerly deferred — is now DONE: both collectors parse `TimeoutExpired.output`.)

**What nuclei needs to work properly:** (1) reachable targets (not blocked —
run a Passive Scan or get the scanner IP allowlisted if coverage collapses),
(2) a template set scoped to the box (severity profile), (3) a memory cap on
small hosts, (4) reasonably fresh templates (image rebuild cadence).

### Other tools (guarded by the 2026-08 audit)

- **amass / nmap timeouts** used to be swallowed → scan read `completed` with a
  truncated surface. Now handled honestly: enumeration/finding tools whose partial
  output is worthwhile **deliver it** on the wall (amass subdomains, nuclei +
  nuclei_network findings — a time-boxed run is a normal result); tools where a
  truncated run is not meaningfully partial raise `ToolTimeout` → scan `partial`
  (nmap). Guards: `test_amass.py::test_timeout_delivers_partial_results`,
  `test_nuclei.py::test_timeout_delivers_partial_findings`,
  `test_nmap.py::TestNmapCollectorFailureModes`.
- **takeover_check** silently dropped `vulnerable` records it couldn't
  fingerprint → subzy field drift hid real takeovers. Now reported. Guard:
  `test_takeover_check.py`.
- **Parsers crash on real (not curated) output**: nuclei/nuclei_network on
  `info: null`, katana on non-dict `request`, domain_security RDAP on missing
  `eventAction`, **takeover_check/subzy on a `null` element in its JSON array**
  (`None.get()` → whole scan flipped to `partial`, hiding real takeover findings;
  a live scanme.nmap.org run exposed it). All guarded by adversarial parser tests.
  takeover_check is now guarded at BOTH layers — the collector filters non-dicts
  and the analyzer skips them (#292 + follow-up). Guard:
  `test_takeover_check.py::TestSubzyNullRecordRegression`.
- **Target blocking is silent**: a blocked scan returns fewer findings but read
  as clean. Now: `endpoints_probed` vs reached counting + a coverage-regression
  finding + `partial` status. Guards: `test_coverage_regression.py`.
