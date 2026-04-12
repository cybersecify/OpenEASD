"""
OpenEASD Django - Entry point.

Starts both the Django web server and Huey task worker.

Run:
    uv run python main.py                  # Dev (web + worker)
    uv run manage.py runserver             # Web server only
    uv run manage.py run_huey              # Task worker only

Production:
    gunicorn openeasd.wsgi:application     # Web server
    uv run manage.py run_huey              # Task worker

CLI scans:
    uv run manage.py run_scan --domain example.com
    uv run manage.py run_daily_scan
    uv run manage.py run_weekly_scan
"""

import subprocess
import sys
import signal
import os


def main():
    """Start both Django web server and Huey task worker."""
    procs = []

    try:
        # Start Huey worker
        huey = subprocess.Popen(
            [sys.executable, "manage.py", "run_huey", "--quiet"],
        )
        procs.append(huey)
        print("Started Huey task worker (PID: {})".format(huey.pid))

        # Start Django dev server (foreground)
        server = subprocess.Popen(
            [sys.executable, "manage.py", "runserver", "0.0.0.0:8000"],
        )
        procs.append(server)
        print("Started Django server at http://0.0.0.0:8000")

        # Wait for either process to exit
        server.wait()

    except KeyboardInterrupt:
        print("\nShutting down...")

    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()


if __name__ == "__main__":
    main()
