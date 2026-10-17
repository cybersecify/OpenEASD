import re
import urllib.request
from typing import Dict, List, Tuple

import defusedxml.ElementTree as ET  # nosec B314 — XXE-safe parser
from defusedxml.common import DefusedXmlException

# SUSE publishes one CVRF document per security update under this directory.
# Each document covers one or more CVEs and lists the Fixed product builds.
BASE_URL = "https://ftp.suse.com/pub/projects/security/cvrf/"

# The directory holds ~46k documents. Fetching all of them on every refresh
# would hammer the mirror and time out CI, so the live fetcher caps the number
# of documents it parses per run. The refresh workflow re-runs periodically and
# the atomic-write guard refuses to clobber good data with an empty result, so
# coverage still grows over successive runs.
MAX_DOCS_PER_RUN = 250

try:
    from apps.nmap.backports import compare_rpm_versions
except ImportError:  # standalone use: python apps/nmap/sources/suse_security.py
    compare_rpm_versions = None


def _local_iter(parent, local_name: str):
    """Yield child/subtree elements whose (namespace-stripped) tag matches."""
    for el in parent.iter():
        if el.tag.split("}")[-1] == local_name:
            yield el


def _split_product(product_id: str) -> Tuple[str, str]:
    """
    Turn a CVRF ProductID into (package name, version-release).

    Real SUSE ProductIDs look like
    ``openSUSE Leap 16.0:jq-1.7.1-160000.5.1`` or
    ``SUSE Linux Enterprise Module for Public Cloud 15 SP5:python311-sqlparse-0.4.4-150400.6.19.1``
    — a product prefix, then an RPM Name-Version-Release. The release is a
    plain dotted number (``150400.6.19.1``, ``160000.5.1``); unlike Red Hat it
    carries no ``.elN`` tag, so the split has to come off the RIGHT: version
    and release are the last two hyphen-separated fields and both start with a
    digit. Splitting on a release-tag heuristic glues the upstream version onto
    the package name (``apache2-2.4.51``) and the entry then never matches the
    bare service name an nmap banner reports.
    """
    text = (product_id or "").strip()
    if ":" in text:
        text = text.split(":", 1)[1]
    if text.count("-") < 2:
        return "", ""

    name, version, release = text.rsplit("-", 2)
    if not name or not version[:1].isdigit() or not release[:1].isdigit():
        return "", ""

    return name, f"{version}-{release}"


def _remember(backports: Dict[str, Dict[str, str]], cve_id: str, name: str,
              version: str) -> None:
    """Store the version, keeping the highest build for a package."""
    known = backports.get(cve_id, {}).get(name)
    if known is None or (
        compare_rpm_versions is not None and compare_rpm_versions(version, known) > 0
    ):
        backports.setdefault(cve_id, {})[name] = version


def parse_suse_cvrf(xml_text: str) -> Dict[str, Dict[str, str]]:
    """
    Parse a single SUSE CVRF document into the backports schema.

    Source: https://ftp.suse.com/pub/projects/security/cvrf/
    Covers openSUSE Leap and SLES (both ship the same CVRF documents).
    Returns: {"CVE-ID": {"package_name": "fixed_version"}}

    Malformed or DTD-bearing XML returns an empty dict rather than raising, so
    one bad document never aborts the whole refresh.
    """
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException, ValueError):
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
                        _remember(backports, cve_id, name, version)

    return backports


def _list_cvrf_documents(html_index: str) -> List[str]:
    """Extract relative .xml hrefs from the directory index page."""
    return re.findall(r'href="([^"]+\.xml)"', html_index or "")


def _sort_newest_first(docs: List[str]) -> List[str]:
    """
    Order documents newest-first so the per-run cap covers recent updates.

    The mirror's index is alphabetical, so a fixed slice off the top always
    takes the same (oldest) files. Filenames carry the advisory year
    (``cvrf-suse-su-2026%3A4109-1.xml``); sort on that descending and push the
    older, undated documents to the end.
    """

    def key(name):
        match = re.search(r"-(\d{4})%3A", name)
        return (int(match.group(1)) if match else 0, name)

    return sorted(docs, key=key, reverse=True)


def fetch_suse_backports() -> Dict[str, Dict[str, str]]:
    """
    Fetch SUSE's CVRF feed and extract backported fixed versions.

    Enumerates the directory index, then parses up to MAX_DOCS_PER_RUN
    documents (newest first) and merges their Fixed product mappings.

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

    docs = _sort_newest_first(_list_cvrf_documents(index_html))
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

        try:
            parsed = parse_suse_cvrf(xml_text)
        except Exception as e:  # nosec B110 — one bad doc must not abort the run
            print(f"Error parsing SUSE CVRF doc {url}: {e}")
            continue

        for cve_id, packages in parsed.items():
            for name, version in packages.items():
                _remember(backports, cve_id, name, version)

    return backports


if __name__ == "__main__":
    b = fetch_suse_backports()
    print(f"Fetched {len(b)} CVEs from SUSE CVRF feed.")
