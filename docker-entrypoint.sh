#!/bin/bash
set -e

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
