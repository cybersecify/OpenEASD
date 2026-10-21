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

## SUSE / openSUSE CVRF source

`fetch_suse_backports()` in `suse_security.py` streams SUSE's official
[CVRF 1.2 advisory archive](https://ftp.suse.com/pub/projects/security/cvrf1.2.tar.bz2)
(`cvrf1.2.tar.bz2`, a large full-history archive) instead of issuing one
request per advisory. It covers SUSE Linux Enterprise / SLES and openSUSE Leap
records present in the upstream feed. A refresh requires downloading and
reading the archive; automated unit tests use small in-memory fixtures instead.

For each advisory, only `Vulnerability/ProductStatuses/Status` entries with
`Type="Fixed"` are considered. A `ProductID` such as
`openSUSE Leap 15.4:postgresql12-timescaledb-2.9.3-bp154.2.3.1` encodes the
product and the **fixed** RPM `name-version-release` (and optional epoch). The
parser uses only those product IDs and, when needed, their `ProductTree`
`FullProductName` equivalents. `Known Affected`, missing versions and other
statuses cannot establish a fix and are excluded. Multiple CVEs in a single
advisory are handled independently.

**Known limitation — release-specific fixes:** CVRF can publish different RPM
versions for a CVE/package on different releases. The current shared JSON
schema (`CVE -> package -> version`) has nowhere to record the SUSE release.
Choosing one arbitrary version would be wrong and could lead to unsafe CVE
suppression. If more than one distinct fixed version is found for a
CVE/package, that package entry is **omitted** and the number of omitted
entries is logged. A future release-aware schema is needed for complete
coverage. The refresh fails rather than replacing existing data on download,
archive or XML parse errors, an empty feed, or an all-ambiguous result.

The current `check_backport()` function does not yet detect SUSE distribution
banners, and `compare_debian_versions()` is not an RPM comparator. These are
separate reported follow-up issues (#575 and #576); this contribution only
collects data and does not alter detection or version comparisons. Run the
parser tests with `pytest tests/unit/test_suse_security.py`; a live archive
smoke test is deliberately separate and requires network access.
