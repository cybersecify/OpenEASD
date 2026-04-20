"""
OpenEASD — single entry point to build and run the complete webapp.

Usage:
    uv run python main.py                   # run (auto-migrate, web + worker)
    uv run python main.py --build           # build React frontend first, then run
    uv run python main.py --build-only      # build frontend and exit
    uv run python main.py --port 9000       # custom port (default: 8000)
    uv run python main.py --no-worker       # web server only, no Huey worker

First run (creates admin user if none exists):
    uv run python main.py --build

Production (gunicorn):
    gunicorn openeasd.wsgi:application      # web server
    uv run manage.py run_huey               # worker (separate terminal)
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
DIST_DIR = FRONTEND_DIR / "dist"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd, cwd=None, check=True):
    """Run a shell command, streaming output. Raises on failure if check=True."""
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, cwd=cwd, check=check)
    return result.returncode == 0


def step(msg):
    print(f"\n{'─' * 50}")
    print(f"  {msg}")
    print(f"{'─' * 50}")


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def build_frontend():
    step("Building React frontend")

    if not shutil.which("npm"):
        print("  ERROR: npm not found. Install Node.js to build the frontend.")
        sys.exit(1)

    if not (FRONTEND_DIR / "node_modules").exists():
        print("  Installing npm dependencies...")
        _run(["npm", "install"], cwd=FRONTEND_DIR)

    _run(["npm", "run", "build"], cwd=FRONTEND_DIR)
    print("  ✓ Frontend built → frontend/dist/")


def check_frontend():
    """Warn if dist/ is missing or stale."""
    if not DIST_DIR.exists() or not any(DIST_DIR.iterdir()):
        print("\n  WARNING: frontend/dist/ is empty or missing.")
        print("  Run with --build to build the React frontend first.")
        print("  The app will serve a blank page until the frontend is built.\n")


def run_migrations():
    step("Running database migrations")
    _run([sys.executable, "manage.py", "migrate", "--run-syncdb"], cwd=BASE_DIR)
    print("  ✓ Database up to date")


def collect_static():
    step("Collecting static files")
    _run(
        [sys.executable, "manage.py", "collectstatic", "--noinput"],
        cwd=BASE_DIR,
    )
    print("  ✓ Static files collected")


def ensure_superuser():
    """Create a default admin user on first run if no users exist."""
    step("Checking for admin user")
    script = (
        "import django; django.setup();"
        "from django.contrib.auth import get_user_model; U = get_user_model();"
        "exists = U.objects.exists();"
        "print('exists' if exists else 'none')"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        env={**os.environ, "DJANGO_SETTINGS_MODULE": "openeasd.settings"},
    )
    if result.stdout.strip() == "none":
        print("  No users found — creating default admin account.")
        print("  Username: admin  |  Password: admin")
        print("  ⚠  Change this password immediately after first login!\n")
        _run(
            [
                sys.executable, "manage.py", "createsuperuser",
                "--noinput",
                "--username", "admin",
                "--email", "admin@localhost",
            ],
            cwd=BASE_DIR,
            check=False,  # may fail if DJANGO_SUPERUSER_PASSWORD not set
        )
        # Set password explicitly
        pw_script = (
            "import django; django.setup();"
            "from django.contrib.auth import get_user_model; U = get_user_model();"
            "u = U.objects.get(username='admin'); u.set_password('admin'); u.save();"
            "print('Password set')"
        )
        subprocess.run(
            [sys.executable, "-c", pw_script],
            cwd=BASE_DIR,
            env={**os.environ, "DJANGO_SETTINGS_MODULE": "openeasd.settings"},
        )
    else:
        print("  ✓ Admin user exists")


def run_server(port: int, with_worker: bool):
    step(f"Starting OpenEASD at http://0.0.0.0:{port}")

    procs = []
    try:
        if with_worker:
            huey = subprocess.Popen(
                [sys.executable, "manage.py", "run_huey", "--quiet"],
                cwd=BASE_DIR,
            )
            procs.append(huey)
            print(f"  ✓ Huey task worker started (PID {huey.pid})")

        server = subprocess.Popen(
            [sys.executable, "manage.py", "runserver", f"0.0.0.0:{port}"],
            cwd=BASE_DIR,
        )
        procs.append(server)
        print(f"  ✓ Django server started  (PID {server.pid})")
        print(f"\n  Open http://localhost:{port}\n")

        server.wait()

    except KeyboardInterrupt:
        print("\n\n  Shutting down...")

    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Build and run the OpenEASD webapp.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build the React frontend before starting",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Build the React frontend and exit (no server)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run the server on (default: 8000)",
    )
    parser.add_argument(
        "--no-worker",
        action="store_true",
        help="Skip starting the Huey task worker",
    )
    args = parser.parse_args()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openeasd.settings")

    if args.build or args.build_only:
        build_frontend()

    if args.build_only:
        print("\n  Done.\n")
        return

    check_frontend()
    run_migrations()
    ensure_superuser()
    run_server(port=args.port, with_worker=not args.no_worker)


if __name__ == "__main__":
    main()
