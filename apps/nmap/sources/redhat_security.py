import urllib.request
import json
from typing import Dict, List

# Upstream: Red Hat Security Data public API (no auth required).
# https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0
BASE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
PER_PAGE = 100

# Only "Fixed" package states carry a usable fixed-in version. Red Hat
# backports aggressively without bumping upstream version strings, so these
# are exactly the records we need to suppress false-positive CVE matches.
# "Affected" and "Will not fix" states carry no fixed_in and are ignored.
_INCLUDED_STATES = {"Fixed"}


def _normalise_fixed_in(fixed_in) -> List[str]:
    """Red Hat reports fixed_in as a string or a list of strings."""
    if fixed_in is None:
        return []
    if isinstance(fixed_in, str):
        return [fixed_in] if fixed_in.strip() else []
    if isinstance(fixed_in, list):
        return [v for v in fixed_in if isinstance(v, str) and v.strip()]
    return []


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

            for pkg in record.get("affected_packages", []) or []:
                state = pkg.get("package_state")
                if state not in _INCLUDED_STATES:
                    continue

                pkg_name = pkg.get("package_name")
                if not pkg_name:
                    continue

                for fixed_version in _normalise_fixed_in(pkg.get("fixed_in")):
                    if cve_id not in backports:
                        backports[cve_id] = {}
                    # Keep the most specific (last) fixed version seen.
                    backports[cve_id][pkg_name] = fixed_version

        page += 1
        # Safety bound: Red Hat has ~10k CVE records; cap well above that.
        if page > 200:
            break

    return backports


if __name__ == "__main__":
    b = fetch_redhat_backports()
    print(f"Fetched {len(b)} CVEs from Red Hat Security Data.")
