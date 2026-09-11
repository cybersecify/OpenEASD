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
        return [int(x) if x.isdigit() else x for x in re.split(r"([0-9]+)", v) if x]

    p1 = parse_parts(v1)
    p2 = parse_parts(v2)

    for a, b in zip(p1, p2):
        if a == b:
            continue
        if type(a) is type(b):
            return 1 if a > b else -1
        # In debian, strings and numbers compare strangely, but casting to str works for most simple cases
        return 1 if str(a) > str(b) else -1

    if len(p1) > len(p2):
        return 1
    elif len(p1) < len(p2):
        return -1
    return 0


def compare_rpm_versions(v1: str, v2: str) -> int:
    """
    RPM-aware version compare (rpmvercmp semantics) over EVR strings.

    Returns 1 if v1 > v2, -1 if v1 < v2, 0 if v1 == v2.

    RPM build versions are Name-Version-Release (e.g. ``8.0p1-1.el9``,
    ``2.4.6-99.el7_9.2``). Debian-style comparison is wrong for these because
    it does not understand release tags, tilde (``~``, sorts before everything)
    or caret (``^``). A leading epoch (``digits:``) is stripped before
    comparison — the upstream feeds and nmap banners disagree on whether the
    epoch is present, and for demotion purposes the V-R portion is what matters.
    """

    def rpmvercmp(a: str, b: str) -> int:
        a = re.sub(r"^\d+:", "", a or "")
        b = re.sub(r"^\d+:", "", b or "")
        i = j = 0
        while i < len(a) or j < len(b):
            # Skip leading non-alphanumeric (and the special ~ ^ markers).
            while i < len(a) and not (a[i].isalnum() or a[i] in "~^"):
                i += 1
            while j < len(b) and not (b[j].isalnum() or b[j] in "~^"):
                j += 1
            if i >= len(a) and j >= len(b):
                return 0

            # Tilde sorts before anything (including end of string).
            if i < len(a) and a[i] == "~":
                if j >= len(b) or b[j] != "~":
                    return -1
                i += 1
                j += 1
                continue
            if j < len(b) and b[j] == "~":
                return 1

            # Caret sorts after end of string but before any real character.
            if i < len(a) and a[i] == "^":
                if j >= len(b) or b[j] != "^":
                    return 1
                i += 1
                j += 1
                continue
            if j < len(b) and b[j] == "^":
                return -1

            # One side ended: the side with a remaining alnum char is greater.
            if i >= len(a) or j >= len(b):
                return -1 if i >= len(a) else 1

            isnum = a[i].isdigit()
            seg1 = ""
            while i < len(a) and (a[i].isdigit() if isnum else a[i].isalpha()):
                seg1 += a[i]
                i += 1
            seg2 = ""
            while j < len(b) and (b[j].isdigit() if isnum else b[j].isalpha()):
                seg2 += b[j]
                j += 1

            if isnum:
                seg1 = seg1.lstrip("0") or "0"
                seg2 = seg2.lstrip("0") or "0"
                if len(seg1) != len(seg2):
                    return 1 if len(seg1) > len(seg2) else -1
                if seg1 != seg2:
                    return 1 if seg1 > seg2 else -1
            else:
                if seg1 != seg2:
                    return 1 if seg1 > seg2 else -1
        return 0

    return rpmvercmp(v1, v2)


# nmap -sV emits distro markers for the Debian/Ubuntu family and the RPM-based
# families (Red Hat / RHEL / Rocky / Alma / CentOS and SUSE / SLES / openSUSE).
# Each rule maps a marker regex to the canonical backports.json key and the
# comparator that understands that distro's build-version format.
_DISTRO_RULES = [
    (re.compile(r"(?i)(ubuntu)"), "ubuntu", "deb"),
    (re.compile(r"(?i)(debian)"), "debian", "deb"),
    (
        re.compile(r"(?i)(rhel|red\s*hat|rocky|alma|centos|oracle\s*linux)"),
        "redhat",
        "rpm",
    ),
    (re.compile(r"(?i)(sles|suse|opensuse|leap)"), "suse", "rpm"),
]

# Debian/Ubuntu build versions: start with a digit, then deb chars; the leading
# separator must not cross a ';' so the "protocol 2.0" form is never captured.
_DEB_VERSION_RE = r"(?:[^;]*?[-; ])\s*(\d[a-z0-9.~+-]*)"

# RPM EVR build versions: a digit-led token that contains a release separator
# (e.g. 2.4.6-99.el7_9.2, 8.0p1-1.el9). Requiring the '-' release part avoids
# capturing a bare distro major version like "Red Hat Enterprise Linux 9".
_RPM_VERSION_RE = r"(?:[^;]*?[-; ])\s*([0-9][0-9A-Za-z._~+:+-]*-[0-9A-Za-z._~+:+-]+)"


def check_backport(product: str, version_string: str, cve: str) -> dict:
    """
    Checks if a CVE has been patched via backport based on the version string.
    Returns a dict with demote information if a backport is applied, else None.
    """
    if not version_string or not product:
        return None

    product = product.lower()

    distro = None
    distro_version = None
    comparator = compare_debian_versions

    # Identify the distro and its build version from nmap extrainfo strings.
    # Examples (Debian/Ubuntu family):
    #   "OpenSSH 9.6p1 Ubuntu-3ubuntu13.4"            → distro_version = "3ubuntu13.4"
    #   "OpenSSH 8.4p1 Debian-5+deb11u3"              → distro_version = "5+deb11u3"
    #   "OpenSSH 9.6p1 Ubuntu Linux; 3ubuntu13.3"     → distro_version = "3ubuntu13.3"
    # RPM family (build versions carry a release tag):
    #   "OpenSSH 8.0p1 Red Hat 8.0p1-1.el9"           → distro=redhat, "8.0p1-1.el9"
    #   "httpd 2.4.6 SUSE 2.4.6-99.el7_9.2"           → distro=suse,   "2.4.6-99.el7_9.2"
    for keyword_re, key, kind in _DISTRO_RULES:
        km = keyword_re.search(version_string)
        if not km:
            continue
        version_re = _RPM_VERSION_RE if kind == "rpm" else _DEB_VERSION_RE
        vm = re.search(version_re, version_string[km.end() :])
        if not vm:
            # Distro keyword present but no usable build version — cannot demote.
            continue
        distro = key
        distro_version = vm.group(1).strip()
        comparator = compare_rpm_versions if kind == "rpm" else compare_debian_versions
        break

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
    if comparator(distro_version, fixed_version) >= 0:
        return {
            "backport_applied": True,
            "first_fixed_in": fixed_version,
        }

    return None
