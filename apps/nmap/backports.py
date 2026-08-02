import json
import re
from pathlib import Path

BACKPORTS_FILE = Path(__file__).parent / "backports.json"

def _load_backports():
    if not BACKPORTS_FILE.exists():
        return {}
    with open(BACKPORTS_FILE, "r") as f:
        return json.load(f)

BACKPORTS = _load_backports()

def compare_debian_versions(v1: str, v2: str) -> int:
    """
    Simplified Debian version compare.
    Returns 1 if v1 > v2, -1 if v1 < v2, 0 if v1 == v2.
    """
    def parse_parts(v):
        return [int(x) if x.isdigit() else x for x in re.split(r'([0-9]+)', v) if x]
    
    p1 = parse_parts(v1)
    p2 = parse_parts(v2)
    
    for a, b in zip(p1, p2):
        if a == b:
            continue
        if type(a) == type(b):
            return 1 if a > b else -1
        # In debian, strings and numbers compare strangely, but casting to str works for most simple cases
        return 1 if str(a) > str(b) else -1
        
    if len(p1) > len(p2):
        return 1
    elif len(p1) < len(p2):
        return -1
    return 0

def check_backport(product: str, version_string: str, cve: str) -> dict:
    """
    Checks if a CVE has been patched via backport based on the version string.
    Returns a dict with demote information if a backport is applied, else None.
    """
    if not version_string or not product:
        return None
        
    product = product.lower()
    
    # Identify distro and distro-specific version from nmap extrainfo strings.
    # Examples:
    #   "OpenSSH 9.6p1 Ubuntu Linux; protocol 2.0"   → no version suffix (skip)
    #   "OpenSSH 9.6p1 Ubuntu-3ubuntu13.4"            → distro_version = "3ubuntu13.4"
    #   "OpenSSH 8.4p1 Debian-5+deb11u3"              → distro_version = "5+deb11u3"
    #   "OpenSSH 9.6p1 Ubuntu Linux; 3ubuntu13.3"     → distro_version = "3ubuntu13.3"
    # We specifically require the suffix to START with a digit to avoid capturing
    # words like "protocol" that appear in the common "Ubuntu Linux; protocol 2.0" format.
    match = re.search(r'(?i)(ubuntu|debian)(?:[^;]*?[-; ])\s*(\d[a-z0-9.~+-]*)', version_string)
    
    distro = None
    distro_version = None
    
    if match:
        distro = match.group(1).lower()
        distro_version = match.group(2).strip()
                
    if not distro or not distro_version:
        return None
        
    distro_data = BACKPORTS.get(distro, {})
    cve_data = distro_data.get(cve)
    if not cve_data:
        return None
        
    # Get the fixed version for this product
    fixed_version = cve_data.get(product)
    if not fixed_version:
        return None
        
    # Compare distro_version with fixed_version
    # If installed version >= fixed_version, it is patched
    if compare_debian_versions(distro_version, fixed_version) >= 0:
        return {
            "backport_applied": True,
            "first_fixed_in": fixed_version
        }
        
    return None
