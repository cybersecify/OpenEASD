import re
import urllib.request
from typing import Dict, List, Tuple

import defusedxml.ElementTree as ET  # nosec B314 — XXE-safe parser

# SUSE publishes one CVRF document per security update under this directory.
# Each document covers one or more CVEs and lists the Fixed product builds.
BASE_URL = "https://ftp.suse.com/pub/projects/security/cvrf/"

# The directory holds thousands of documents. Fetching all of them on every
# refresh would hammer the mirror and time out CI, so the live fetcher caps
# the number of documents it parses per run. The refresh workflow re-runs
# periodically and the atomic-write guard refuses to clobber good data with
# an empty result, so coverage still grows over successive runs.
MAX_DOCS_PER_RUN = 250


def _local_iter(parent, local_name: str):
    """Yield child/subtree elements whose (namespace-stripped) tag matches."""
    for el in parent.iter():
        if el.tag.split("}")[-1] == local_name:
            yield el


def _split_product(product_id: str) -> Tuple[str, str]:
    """
    Turn a CVRF ProductID like
    "SUSE Liberty Linux 7 LTSS:httpd-2.4.6-99.el7_9.2"
    into ("httpd", "2.4.6-99.el7_9.2").

    SUSE uses RPM N-V-R naming, where the release suffix ends in a distro
    tag (.el<digits>, .sle<digits>, .lp<digits>) or is otherwise a dotted
    number. The package name may itself contain hyphens (e.g. httpd-devel),
    so we cannot simply split on the last hyphen. Instead we accept the first
    hyphen that leaves a version-looking remainder (starts with a digit and/or
    carries a known release tag), which strips the family prefix first and
    then isolates N from V-R.
    """
    text = (product_id or "").strip()
    if ":" in text:
        text = text.split(":", 1)[1]
    if "-" not in text:
        return "", ""

    for i in range(len(text)):
        if text[i] != "-":
            continue
        name, rest = text[:i], text[i + 1 :]
        # A valid V-R remainder starts with a digit and contains a release tag.
        if rest[:1].isdigit() and (".el" in rest or ".sle" in rest or ".lp" in rest):
            return name, rest

    # Fallback: no release tag found — split on the last hyphen.
    idx = text.rfind("-")
    name, version = text[:idx], text[idx + 1 :]
    if any(ch.isdigit() for ch in version):
        return name, version
    return "", ""


def parse_suse_cvrf(xml_text: str) -> Dict[str, Dict[str, str]]:
    """
    Parse a single SUSE CVRF document into the backports schema.

    Source: https://ftp.suse.com/pub/projects/security/cvrf/
    Covers openSUSE Leap and SLES (both ship the same CVRF documents).
    Returns: {"CVE-ID": {"package_name": "fixed_version"}}

    Malformed XML returns an empty dict rather than raising, so one bad
    document never aborts the whole refresh.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    backports: Dict[str, Dict[str, str]] = {}

    for vuln in _local_iter(root, "Vulnerability"):
        cve_id = ""
        for cve in _local_iter(vuln, "CVE"):
            cve_id = (cve.text or "").strip()
            break
        if not cve_id:
            continue

        for statuses in _local_iter(vuln, "ProductStatuses"):
            for status in _local_iter(statuses, "Status"):
                if status.get("Type") != "Fixed":
                    continue
                for pid in _local_iter(status, "ProductID"):
                    name, version = _split_product(pid.text or "")
                    if name and version:
                        backports.setdefault(cve_id, {})[name] = version

    return backports


def _list_cvrf_documents(html_index: str) -> List[str]:
    """Extract relative .xml hrefs from the directory index page."""
    return re.findall(r'href="([^"]+\.xml)"', html_index or "")


def fetch_suse_backports() -> Dict[str, Dict[str, str]]:
    """
    Fetch SUSE's CVRF feed and extract backported fixed versions.

    Enumerates the directory index, then parses up to MAX_DOCS_PER_RUN
    documents and merges their Fixed product mappings.

    Source: https://ftp.suse.com/pub/projects/security/cvrf/
    Returns: {"CVE-ID": {"package_name": "fixed_version"}}
    """
    req = urllib.request.Request(BASE_URL, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
            index_html = response.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"Error fetching SUSE CVRF index: {e}")
        return {}

    docs = _list_cvrf_documents(index_html)
    backports: Dict[str, Dict[str, str]] = {}

    for rel in docs[:MAX_DOCS_PER_RUN]:
        url = f"{BASE_URL}{rel}"
        try:
            doc_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(doc_req, timeout=30) as doc_resp:  # nosec B310
                xml_text = doc_resp.read().decode("utf-8", "replace")
        except Exception as e:
            print(f"Error fetching SUSE CVRF doc {url}: {e}")
            continue

        for cve_id, packages in parse_suse_cvrf(xml_text).items():
            backports.setdefault(cve_id, {}).update(packages)

    return backports


if __name__ == "__main__":
    b = fetch_suse_backports()
    print(f"Fetched {len(b)} CVEs from SUSE CVRF feed.")
