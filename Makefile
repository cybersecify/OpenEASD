PORT := 8001

.PHONY: setup dev backend frontend migrate makemigrations shell createsuperuser \
        lint format test clean

## ── First-time setup ────────────────────────────────────────────────────────

setup:
	@echo "==> Syncing Python environment (uv)..."
	uv sync --group dev
	@echo "==> Running database migrations..."
	@mkdir -p data
	uv run manage.py migrate
	@echo "==> Installing frontend dependencies..."
	cd frontend && npm install
	@echo ""
	@echo "  Done. Start dev with: make dev"

## ── Development servers ─────────────────────────────────────────────────────

## Run Django + Vite dev server together (Ctrl-C stops both)
## React served by Vite at http://localhost:5173 (proxies /api/ to Django)
dev:
	@trap 'kill 0' SIGINT SIGTERM EXIT; \
	(cd frontend && npm run dev) & \
	(uv run manage.py runserver $(PORT)) & \
	wait

## Run only the Django dev server
backend:
	uv run manage.py runserver $(PORT)

## Build frontend once
frontend:
	cd frontend && npm run build

## ── Database ────────────────────────────────────────────────────────────────

migrate:
	uv run manage.py migrate

makemigrations:
	uv run manage.py makemigrations

## ── Django utilities ────────────────────────────────────────────────────────

shell:
	uv run manage.py shell

createsuperuser:
	uv run manage.py createsuperuser

## ── Code quality ────────────────────────────────────────────────────────────

lint:
	uv run ruff check apps/

format:
	uv run black apps/
	uv run ruff check apps/ --fix

test:
	uv run pytest tests/ --ignore=tests/unit/test_domain_security.py

test-all:
	uv run pytest tests/

## ── Cleanup ─────────────────────────────────────────────────────────────────

clean:
	rm -rf .venv frontend/node_modules frontend/dist staticfiles
	@echo "Removed .venv, node_modules, dist, staticfiles"
