import json
from pathlib import Path
import sys

# Ensure we can import from sources if this is run as a script
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from sources.ubuntu_usn import fetch_ubuntu_backports
from sources.debian_security_tracker import fetch_debian_backports
from sources.alpine_secdb import fetch_alpine_backports

try:
    from sources.redhat_security import fetch_redhat_backports
except ImportError:
    fetch_redhat_backports = None

try:
    from sources.suse_security import fetch_suse_backports
except ImportError:
    fetch_suse_backports = None

try:
    from django.core.management.base import BaseCommand
except ImportError:

    class BaseCommand:
        pass


def do_refresh():
    feeds = [
        ("ubuntu", fetch_ubuntu_backports),
        ("debian", fetch_debian_backports),
        ("alpine", fetch_alpine_backports),
    ]
    if fetch_redhat_backports is not None:
        feeds.append(("redhat", fetch_redhat_backports))
    if fetch_suse_backports is not None:
        feeds.append(("suse", fetch_suse_backports))

    results = {}
    for name, fetcher in feeds:
        print(f"Fetching backports from {name.capitalize()}...")
        try:
            data = fetcher()
        except Exception as e:  # nosec B110 — a feed crash must not abort the run
            print(f"ERROR fetching {name}: {e}")
            data = {}
        print(f"Got {len(data)} CVEs from {name.capitalize()}.")
        results[name] = data

    # Per-feed tolerant guard. A slow/empty upstream must not clobber the good
    # feeds: keep the known-good data, warn, and skip the empty one instead of
    # aborting the whole refresh. We only refuse to write when EVERY feed is
    # empty (nothing usable to merge) or when a feed that previously had data
    # in backports.json came back empty this run (a likely upstream regression
    # worth surfacing loudly) — in that case we still keep the previous file.
    combined = {}
    empty_feeds = []
    for name, data in results.items():
        if data:
            combined[name] = data
        else:
            empty_feeds.append(name)

    if empty_feeds:
        print(
            f"WARNING: feed(s) returned empty, skipping in merge: {', '.join(empty_feeds)}"
        )

    if not combined:
        print(
            "ERROR: every feed returned empty — refusing to write an empty backports.json."
        )
        sys.exit(1)

    output_path = Path(__file__).resolve().parent.parent.parent / "backports.json"

    # Load any existing data so a feed that is temporarily empty keeps its
    # previously-merged entries instead of being dropped from the file.
    existing = {}
    if output_path.exists():
        try:
            existing = json.loads(output_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}

    for name, data in results.items():
        if not data:
            # Preserve the previous good slice for this feed.
            if name in existing:
                combined[name] = existing[name]

    # Atomic write: write to .tmp first, then replace, so a crash/SIGKILL mid-write
    # never leaves backports.json empty or half-written.
    import os

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
