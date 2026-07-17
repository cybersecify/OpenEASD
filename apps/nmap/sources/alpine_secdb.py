import urllib.request
import json
from typing import Dict

def fetch_alpine_backports() -> Dict[str, Dict[str, str]]:
    """
    Fetches the Alpine Linux Security Database JSON feeds and extracts backported versions.
    Source: https://secdb.alpinelinux.org/
    Returns: {"CVE-ID": {"package_name": "fixed_version"}}
    """
    base_url = "https://secdb.alpinelinux.org"
    branches = ["v3.20", "v3.21", "edge"]
    repos = ["main", "community"]
    
    backports = {}

    for branch in branches:
        for repo in repos:
            url = f"{base_url}/{branch}/{repo}.json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            try:
                with urllib.request.urlopen(req, timeout=30) as response:
                    data = json.loads(response.read().decode('utf-8'))
            except Exception as e:
                print(f"Error fetching Alpine SecDB ({url}): {e}")
                continue

            packages = data.get('packages', [])
            for pkg_entry in packages:
                pkg = pkg_entry.get('pkg', {})
                pkg_name = pkg.get('name')
                secfixes = pkg.get('secfixes', {})
                
                if not pkg_name or not secfixes:
                    continue

                for fixed_version, cve_list in secfixes.items():
                    for cve in cve_list:
                        if cve not in backports:
                            backports[cve] = {}
                        # If a CVE already has a fixed version, overwriting is acceptable
                        # because we want to track any valid fixed version for it.
                        backports[cve][pkg_name] = fixed_version

    return backports

if __name__ == "__main__":
    b = fetch_alpine_backports()
    print(f"Fetched {len(b)} CVEs from Alpine.")
