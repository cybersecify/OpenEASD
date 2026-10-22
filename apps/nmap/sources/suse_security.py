"""SUSE/openSUSE security fixes from SUSE's official CVRF 1.2 advisory archive.

Upstream: https://ftp.suse.com/pub/projects/security/cvrf1.2.tar.bz2
Covers advisory records for SUSE Linux Enterprise (including SLES) and openSUSE
Leap, as available in the upstream archive.  Only ``Status Type="Fixed"``
package identifiers are evidence of a fixed version.  A CVRF document can
contain many CVEs, packages and supported releases.

The shared OpenEASD contract cannot represent different fixes for different
releases: ``{CVE: {package: version}}``.  Therefore *conflicting* versions for
one CVE/package are omitted, not overwritten or incorrectly generalized to
all products.  See sources/README.md for this deliberate limitation.
"""

import logging
import re
import tarfile
import urllib.request
import defusedxml.ElementTree as ET
from collections import defaultdict
from typing import Dict

LOGGER = logging.getLogger(__name__)
CVRF_ARCHIVE_URL = "https://ftp.suse.com/pub/projects/security/cvrf1.2.tar.bz2"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}$")
_ADVISORY_RE = re.compile(r"(?:^|/)cvrf-(?:opensuse|suse)-su-\d{4}:\d+-\d+\.xml$")
# RPM's name-version-release syntax; the version must begin with a digit (or epoch).
_NVR_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_+][A-Za-z0-9_.+~-]*)-"
    r"(?P<version>(?:\d+:)?\d[^\s/]*)-"
    r"(?P<release>[^\s/:]+)$"
)
_MAX_ADVISORY_SIZE = 16 * 1024 * 1024
_MAX_ADVISORIES = 100_000
_MAX_TOTAL_UNCOMPRESSED = 4 * 1024 * 1024 * 1024


def _package_fix(product_id: str) -> tuple[str, str] | None:
    """Decode a product-scoped CVRF fixed ProductID into (package, EVR).

    Example (as documented by SUSE CVRF consumers):
    ``openSUSE Leap 15.4:postgresql12-timescaledb-2.9.3-bp154.2.3.1``.
    The product scope is checked before extracting the RPM name/version/release.
    """
    product, delimiter, nvr = product_id.partition(":")
    if not delimiter or not product.casefold().startswith(("suse", "opensuse", "sles", "sle ")):
        return None
    match = _NVR_RE.fullmatch(nvr.strip())
    if not match:
        return None
    return match.group("name"), f'{match.group("version")}-{match.group("release")}'


def parse_suse_cvrf(xml_bytes: bytes) -> Dict[str, Dict[str, set[str]]]:
    """Extract evidence of fixes from one SUSE CVRF XML document.

    Keeps a *set* of versions per CVE/package so that a caller can identify
    ambiguity across SUSE releases or across multiple advisories.  Parsing a
    malformed document raises ``ET.ParseError`` instead of returning an
    apparently successful partial result.
    """
    # ElementTree does not resolve external entities. Reject DTDs explicitly.
    if b"<!DOCTYPE" in xml_bytes.upper() or b"<!ENTITY" in xml_bytes.upper():
        raise ValueError("DTD/entity declarations are not supported in SUSE CVRF")
    root = ET.fromstring(xml_bytes)
    result: Dict[str, Dict[str, set[str]]] = {}

    # ProductID may be a ProductTree identifier rather than the literal NVR.
    names = {
        item.get("ProductID"): (item.text or "").strip()
        for item in root.findall(".//{*}ProductTree//{*}FullProductName")
        if item.get("ProductID") and (item.text or "").strip()
    }
    for vuln in root.findall(".//{*}Vulnerability"):
        cve = (vuln.findtext("{*}CVE") or "").strip()
        if not _CVE_RE.fullmatch(cve):
            continue
        statuses = vuln.findall("{*}ProductStatuses/{*}Status")
        # Exclude inconsistent products explicitly reported as both fixed and
        # affected/unresolved within one vulnerability.
        other_ids = {
            (p.text or "").strip()
            for status in statuses
            if status.get("Type", "").casefold() != "fixed"
            for p in status.findall("{*}ProductID")
        }
        for status in statuses:
            if status.get("Type", "").casefold() != "fixed":
                continue
            for node in status.findall("{*}ProductID"):
                product_id = (node.text or "").strip()
                if not product_id or product_id in other_ids:
                    continue
                fix = _package_fix(names.get(product_id, product_id))
                if fix is not None:
                    package, version = fix
                    result.setdefault(cve, {}).setdefault(package, set()).add(version)
    return result


def fetch_suse_backports() -> Dict[str, Dict[str, str]]:
    """Stream the SUSE CVRF 1.2 archive and normalize unambiguous fixed packages.

    Streams a single upstream download without extracting archive paths to disk
    or loading the entire compressed archive in memory.  Network errors,
    truncated archives, invalid XML, and empty feeds raise exceptions; a refresh
    must never replace existing backport data after a partial fetch.
    """
    req = urllib.request.Request(
        CVRF_ARCHIVE_URL,
        headers={"User-Agent": "OpenEASD-Security-Feeds/1.0", "Accept": "application/x-bzip2"},
    )
    versions: dict[tuple[str, str], set[str]] = defaultdict(set)
    count = 0
    total_size = 0
    with urllib.request.urlopen(req, timeout=60) as response:  # nosec B310
        with tarfile.open(fileobj=response, mode="r|bz2") as archive:
            for member in archive:
                if not _ADVISORY_RE.search(member.name) or not member.isfile():
                    continue
                count += 1
                if count > _MAX_ADVISORIES:
                    raise ValueError("SUSE CVRF archive exceeds advisory limit")
                if member.size > _MAX_ADVISORY_SIZE:
                    raise ValueError(f"SUSE CVRF advisory too large: {member.name}")
                total_size += member.size
                if total_size > _MAX_TOTAL_UNCOMPRESSED:
                    raise ValueError("SUSE CVRF archive exceeds uncompressed size limit")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"Unable to read SUSE CVRF advisory: {member.name}")
                with source:
                    evidence = parse_suse_cvrf(source.read())
                for cve, packages in evidence.items():
                    for package, fixes in packages.items():
                        versions[cve, package].update(fixes)

    if count == 0 or not versions:
        raise ValueError("SUSE CVRF archive has no usable fixed-version records")

    result: Dict[str, Dict[str, str]] = {}
    ambiguous = 0
    for (cve, package), fixed_versions in sorted(versions.items()):
        if len(fixed_versions) == 1:
            result.setdefault(cve, {})[package] = next(iter(fixed_versions))
        else:
            ambiguous += 1
    if ambiguous:
        LOGGER.warning(
            "Omitted %d SUSE CVE/package records with conflicting release-specific fixed versions",
            ambiguous,
        )
    if not result:
        raise ValueError("All SUSE CVRF fixed-version records are release-ambiguous")
    return result
