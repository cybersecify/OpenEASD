import urllib.request
import json
from typing import Dict

def fetch_ubuntu_backports() -> Dict[str, Dict[str, str]]:
    """
    Fetches the Ubuntu Security Notices JSON feed and extracts backported versions.
    Returns: {"CVE-ID": {"package_name": "fixed_version"}}
    """
    url = "https://ubuntu.com/security/notices.json"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Error fetching Ubuntu USN: {e}")
        return {}

    backports = {}
    
    for notice in data.get('notices', []):
        cves = notice.get('cves_ids', [])
        release_packages = notice.get('release_packages', {})
        
        # We only care about LTS or specific supported releases (e.g., jammy, noble)
        # But we can extract all fixed versions for simplicity in the analyzer
        for release, packages in release_packages.items():
            for pkg in packages:
                pkg_name = pkg.get('name')
                pkg_version = pkg.get('version')
                
                if not pkg_name or not pkg_version:
                    continue
                
                for cve in cves:
                    if cve not in backports:
                        backports[cve] = {}
                    # We store the latest fixed version. 
                    # If it's already there, we can overwrite or keep. Overwriting is fine.
                    backports[cve][pkg_name] = pkg_version

    return backports

if __name__ == "__main__":
    b = fetch_ubuntu_backports()
    print(f"Fetched {len(b)} CVEs from Ubuntu.")
