import urllib.request
import json
from typing import Dict

def fetch_debian_backports() -> Dict[str, Dict[str, str]]:
    """
    Fetches the Debian Security Tracker JSON feed and extracts backported versions.
    Returns: {"CVE-ID": {"package_name": "fixed_version"}}
    """
    url = "https://security-tracker.debian.org/tracker/data/json"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Error fetching Debian Security Tracker: {e}")
        return {}

    backports: Dict[str, Dict[str, Dict[str, str]]] = {}

    # Structure: data[package_name][CVE_ID]["releases"][release_name] = {"status": "resolved", "fixed_version": "..."}
    for pkg_name, cve_dict in data.items():
        for cve_id, cve_info in cve_dict.items():
            releases = cve_info.get("releases", {})

            # Target Bookworm (Debian 12) then Bullseye (Debian 11)
            # Store per-release to avoid later releases overwriting earlier ones.
            for release_name in ["bookworm", "bullseye"]:
                release_info = releases.get(release_name, {})
                status = release_info.get("status")
                fixed_version = release_info.get("fixed_version")

                if status == "resolved" and fixed_version and fixed_version != "0":
                    if cve_id not in backports:
                        backports[cve_id] = {}
                    if release_name not in backports[cve_id]:
                        backports[cve_id][release_name] = {}
                    backports[cve_id][release_name][pkg_name] = fixed_version

    return backports

if __name__ == "__main__":
    b = fetch_debian_backports()
    print(f"Fetched {len(b)} CVEs from Debian.")
