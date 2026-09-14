import urllib.request
import json
import re
from typing import Dict, Optional, Tuple

# Upstream: Red Hat Security Data public API (no auth required).
# https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0
BASE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
PER_PAGE = 100

# This feed carries no per-entry fix state and no `fixed_in` field. The
# `package_state` entries (product_name / fix_state / package_name) are a
# separate top-level field that carries no version, and they are null on the
# list endpoint. What does carry a version is `affected_packages`: a list of
# Name-Version-Release strings that mirrors `affected_release[].package` on the
# per-CVE detail endpoint — i.e. the builds shipped by an RHSA that fix the
# CVE. A CVE Red Hat never fixed (Will not fix / Affected) simply has an empty
# list, so it contributes nothing and needs no state filter.
_NVR_RE = re.compile(r"^(?P<name>.+)-(?P<version>[^-]+)-(?P<release>[^-]+)$")
_EPOCH_RE = re.compile(r"^\d+:")
# RHEL 8/9/10 builds only. The same field also lists container and module
# builds (odf4/odf-console-rhel9:v4.15.0-57, virt:rhel-8100020240314...),
# which carry no .elN release tag and cannot be matched against an nmap banner.
_RHEL_RELEASE_RE = re.compile(r"\.el(?:8|9|10)(?![0-9])")

try:
    from apps.nmap.backports import compare_rpm_versions
except ImportError:  # standalone use: python apps/nmap/sources/redhat_security.py
    compare_rpm_versions = None


def parse_fixed_build(entry) -> Optional[Tuple[str, str]]:
    """
    Splits a Red Hat Name-Version-Release string into (package, version-release).

    The epoch is dropped: nmap banners and the feed disagree on whether it is
    present, and the V-R portion is what a banner can be compared against.
    Returns None for container/module builds, for non rpm entries and for
    anything that is not a RHEL 8/9/10 build.
    """
    if not isinstance(entry, str):
        return None

    match = _NVR_RE.match(entry.strip())
    if not match:
        return None

    name = match.group("name").strip()
    version = _EPOCH_RE.sub("", match.group("version").strip())
    release = match.group("release").strip()

    # Container builds ("io.quarkus/quarkus-...:3.2.11.Final-redhat-00001") and
    # module streams ("virt:rhel-810...") share this field. An rpm package name
    # holds neither a slash nor a colon, and its version starts with a digit.
    if not name or "/" in name or ":" in name or not version[:1].isdigit():
        return None
    if not _RHEL_RELEASE_RE.search(release):
        return None

    return name, f"{version}-{release}"


def fetch_redhat_backports() -> Dict[str, Dict[str, str]]:
    """
    Fetches Red Hat's public security data feed and extracts backported
    fixed versions.

    Covers RHEL 8/9/10. Rocky Linux and AlmaLinux consume the same upstream
    errata data and share package state with upstream, so no separate
    parsing is required.

    Source: https://access.redhat.com/hydra/rest/securitydata/cve.json
    Returns: {"CVE-ID": {"package_name": "fixed_version"}}
    """
    backports: Dict[str, Dict[str, str]] = {}
    page = 1

    while True:
        url = f"{BASE_URL}?page={page}&per_page={PER_PAGE}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        try:
            with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
                data = json.loads(response.read().decode("utf-8"))
        except Exception as e:
            print(f"Error fetching Red Hat Security Data (page={page}): {e}")
            break

        # The endpoint returns a list of CVE records; an empty list ends paging.
        if not isinstance(data, list) or not data:
            break

        for record in data:
            cve_id = record.get("CVE")
            if not cve_id:
                continue

            for entry in record.get("affected_packages") or []:
                parsed = parse_fixed_build(entry)
                if parsed is None:
                    continue

                pkg_name, fixed_version = parsed
                known = backports.get(cve_id, {}).get(pkg_name)
                # Keep the highest fixed build: a host on a newer stream must
                # not be demoted by the lower build number of an older stream.
                if known is None or (
                    compare_rpm_versions is not None
                    and compare_rpm_versions(fixed_version, known) > 0
                ):
                    backports.setdefault(cve_id, {})[pkg_name] = fixed_version

        page += 1
        # Safety bound: Red Hat has ~10k CVE records; cap well above that.
        if page > 200:
            break

    return backports


if __name__ == "__main__":
    b = fetch_redhat_backports()
    print(f"Fetched {len(b)} CVEs from Red Hat Security Data.")
