import os
import json
from pathlib import Path
import sys

# Ensure we can import from sources if this is run as a script
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from sources.ubuntu_usn import fetch_ubuntu_backports
from sources.debian_security_tracker import fetch_debian_backports

try:
    from django.core.management.base import BaseCommand
except ImportError:
    class BaseCommand:
        pass

def do_refresh():
    print("Fetching backports from Ubuntu...")
    ubuntu_backports = fetch_ubuntu_backports()
    print(f"Got {len(ubuntu_backports)} CVEs from Ubuntu.")

    print("Fetching backports from Debian...")
    debian_backports = fetch_debian_backports()
    print(f"Got {len(debian_backports)} CVEs from Debian.")

    # Guard: abort if either feed returned empty to avoid clobbering valid data
    if not ubuntu_backports or not debian_backports:
        print("ERROR: one or more feeds returned empty — aborting write to protect existing data.")
        sys.exit(1)

    combined = {
        "ubuntu": ubuntu_backports,
        "debian": debian_backports
    }

    output_path = Path(__file__).resolve().parent.parent.parent / "backports.json"

    # Atomic write: write to .tmp first, then replace, so a crash/SIGKILL mid-write
    # never leaves backports.json empty or half-written.
    import tempfile, os
    tmp_path = output_path.with_suffix(".json.tmp")
    print(f"Writing to {output_path} (atomic)...")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, sort_keys=True)
    os.replace(tmp_path, output_path)

    print("Done!")

class Command(BaseCommand):
    help = "Refreshes backports.json from upstream security feeds"

    def handle(self, *args, **options):
        do_refresh()

if __name__ == "__main__":
    do_refresh()

