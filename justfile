# OpenEASD task runner (mirrors the Makefile; adds `just ci` = the full CI locally).
# `just` docs: https://github.com/casey/just  ·  install: brew install just
#
# List recipes:  just            (or: just --list)

PORT := "8001"

# Default: show the recipe list
default:
    @just --list

# ── First-time setup ─────────────────────────────────────────────────────────

# Sync the Python env, migrate, install frontend deps
setup:
    uv sync --group dev
    uv run manage.py migrate
    cd frontend && npm install
    @echo "Done. Start dev with: just dev"

# ── Development ───────────────────────────────────────────────────────────────

# Django ({{PORT}}) + DBOS worker + Vite dev server together (Ctrl-C stops all)
dev:
    #!/usr/bin/env bash
    (cd frontend && npm run dev) & \
    (uv run manage.py runserver {{PORT}}) & \
    (uv run manage.py dbos_worker) & \
    wait || kill 0

# Only the DBOS worker (required for scans to execute)
worker:
    uv run manage.py dbos_worker

# Only the Django dev server
backend:
    uv run manage.py runserver {{PORT}}

# Build the frontend bundle once
frontend:
    cd frontend && npm run build

# ── Database ──────────────────────────────────────────────────────────────────

migrate:
    uv run manage.py migrate

makemigrations:
    uv run manage.py makemigrations

shell:
    uv run manage.py shell

createsuperuser:
    uv run manage.py createsuperuser

# ── Code quality ──────────────────────────────────────────────────────────────

# Ruff lint (same scope as CI: apps/ openeasd/ tests/)
lint:
    uv run ruff check apps/ openeasd/ tests/

# Auto-format + fix
format:
    uv run black apps/
    uv run ruff check apps/ openeasd/ tests/ --fix

# Fast test suite (excludes the slow real-network domain_security tests)
test:
    uv run pytest tests/ --ignore=tests/unit/test_domain_security.py

# The full suite including the slow domain_security tests
test-all:
    uv run pytest tests/

# ── CI (run the whole pipeline locally, matching .github/workflows/ci.yml) ─────

# Backend CI: ruff + pytest(80% gate) + bandit + pip-audit (needs Postgres via DB_* env)
ci-backend:
    uv run ruff check apps/ openeasd/ tests/
    uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q \
        --cov --cov-report=term-missing --cov-fail-under=80
    uv run bandit -r apps/ openeasd/ -ll -x tests/
    uv run pip-audit --ignore-vuln PYSEC-2025-183

# Frontend CI: vitest + production build (mirrors the ci.yml `frontend` job)
ci-frontend:
    cd frontend && npm run test:run
    cd frontend && npm run build

# Full local CI = backend + frontend (what must be green before pushing)
ci: ci-backend ci-frontend
    @echo "✅ local CI passed (ruff + pytest+coverage + bandit + pip-audit + vitest + build)"

# ── Docker (production-like 3-container stack: db + web + worker) ──────────────

# Build + start the 3-container stack (http://localhost:8000)
up:
    docker compose up -d --build

# Stop the stack (keep the db volume)
down:
    docker compose down

# Tail all container logs
logs:
    docker compose logs -f

# Stack status
ps:
    docker compose ps

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
    rm -rf .venv frontend/node_modules frontend/dist staticfiles
    @echo "Removed .venv, node_modules, dist, staticfiles"
