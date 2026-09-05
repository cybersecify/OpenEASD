#!/bin/bash
set -e

# OPENEASD_ROLE selects what this container does (Postgres + DBOS topology):
#   web    (default) — runs migrations + collectstatic + admin setup, then the
#                      command (gunicorn). One web/init container owns the schema.
#   worker            — runs the DBOS worker; does NOT touch the schema. It waits
#                      until the web container has applied all migrations, so it
#                      never races the DDL or starts against a half-built schema.
OPENEASD_ROLE="${OPENEASD_ROLE:-web}"

# Wait for PostgreSQL before doing anything DB-bound (both roles).
echo "[entrypoint] Waiting for PostgreSQL to accept connections..."
python - <<'PYEOF'
import os, time
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openeasd.settings")
django.setup()
from django.db import connections
from django.db.utils import OperationalError
for attempt in range(60):
    try:
        connections["default"].cursor()
        print("[entrypoint] PostgreSQL is up")
        break
    except OperationalError:
        time.sleep(2)
else:
    raise SystemExit("[entrypoint] PostgreSQL did not become available in time")
PYEOF

if [ "$OPENEASD_ROLE" = "worker" ]; then
    # Don't run DDL in the worker; wait for the web container's migrations so the
    # DBOS worker launches against a fully-migrated schema.
    echo "[entrypoint] worker role — waiting for migrations to be applied..."
    until python manage.py migrate --check >/dev/null 2>&1; do
        echo "[entrypoint] migrations not yet applied — retrying in 3s"
        sleep 3
    done
    echo "[entrypoint] migrations present — starting worker"
    exec "$@"
fi

echo "[entrypoint] Running database migrations..."
python manage.py migrate --run-syncdb

echo "[entrypoint] Collecting static files..."
python manage.py collectstatic --noinput --clear

echo "[entrypoint] Ensuring admin user..."
python - <<'PYEOF'
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openeasd.settings")
import django
django.setup()
from django.contrib.auth import get_user_model
from apps.core.dashboard.models import UserProfile
U = get_user_model()
if not U.objects.exists():
    u = U.objects.create_superuser("admin", "admin@localhost", "admin")
    p, _ = UserProfile.objects.get_or_create(user=u)
    p.must_change_password = True
    p.save()
    print("[entrypoint] Created admin user — password must be changed on first login")
else:
    u = U.objects.filter(username="admin").first()
    if u and u.check_password("admin"):
        p, _ = UserProfile.objects.get_or_create(user=u)
        p.must_change_password = True
        p.save()
        print("[entrypoint] Default password detected — must_change_password flagged")
    else:
        print("[entrypoint] Admin user already configured")
PYEOF

# Probe external tools (subfinder, dnsx, naabu, httpx, nuclei, nmap, amass)
# with tiny known-good targets. Non-fatal: always exits 0 — the point is
# observability in the container logs, not gating startup. If any tool fails,
# scans using it will silently return empty results until you fix it.
echo "[entrypoint] Running external tool healthcheck..."
python manage.py tools_healthcheck || true

exec "$@"
