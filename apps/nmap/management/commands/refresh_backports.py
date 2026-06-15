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
    
    combined = {
        "ubuntu": ubuntu_backports,
        "debian": debian_backports
    }
    
    output_path = Path(__file__).resolve().parent.parent.parent / "backports.json"
    
    print(f"Writing to {output_path}...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)
    
    print("Done!")

class Command(BaseCommand):
    help = "Refreshes backports.json from upstream security feeds"

    def handle(self, *args, **options):
        do_refresh()

if __name__ == "__main__":
    do_refresh()

