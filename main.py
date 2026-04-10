"""
OpenEASD Django - Entry point.

Run via Django manage.py:
    python manage.py runserver          # Dev server
    gunicorn openeasd.wsgi:application  # Production

Celery:
    celery -A openeasd worker
    celery -A openeasd beat

CLI scans:
    python manage.py run_scan --domain example.com --scan-type full
    python manage.py run_daily_scan
    python manage.py run_weekly_scan
"""

import subprocess
import sys


def main():
    subprocess.run(
        [sys.executable, "manage.py", "runserver", "0.0.0.0:8000"],
        check=True,
    )


if __name__ == "__main__":
    main()
