# OpenEASD Backports Sources

This directory contains parsers for various upstream Linux distribution security feeds.
These parsers fetch and transform the raw security data into a normalised format used by OpenEASD.

## How to add a new distro source

1. **Create a new Python file** in this directory (e.g., `alpine_secdb.py`).
2. **Implement a fetch function** (e.g., `fetch_alpine_backports()`) that:
   - Downloads the respective security feed (JSON/XML/OVAL).
   - Parses the feed to extract resolved CVEs and their fixed package versions.
   - Returns a nested dictionary mapping CVE IDs to package fixed versions:
     ```python
     {
       "CVE-2024-XXXX": {
         "package_name": "fixed_version"
       }
     }
     ```
3. **Update the orchestrator** in `apps/nmap/management/commands/refresh_backports.py`:
   - Import your new parser.
   - Call it inside the `do_refresh()` function.
   - Merge its results into the `combined` dictionary under the distro's key (e.g., `"alpine": alpine_backports`).
4. **Add unit tests** in `tests/test_backports_refresh.py` with mock data for your new feed.

This approach ensures the heavy lifting of data normalisation is done offline, and OpenEASD users get fast, air-gapped CVE suppression.
