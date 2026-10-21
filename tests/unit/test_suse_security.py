"""Offline SUSE CVRF 1.2 parser tests.

Fixtures use documented CVRF field names and product identifiers. The trivy
CVE/version example is confirmed on SUSE's CVE-2026-50195 page; the XML itself
is a deliberately minimal representative fixture, NOT a fetched upstream XML.
"""

import io
import tarfile
import urllib.error
from unittest.mock import patch

import pytest

from apps.nmap.sources.suse_security import (
    fetch_suse_backports,
    parse_suse_cvrf,
    _package_fix,
)


def advisory(cves=("CVE-2026-50195",), packages=None, namespace=True):
    if packages is None:
        packages = ["SUSE Package Hub 15 SP7:trivy-0.71.2-bp157.2.12.1"]
    xmlns = ' xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.2"' if namespace else ""
    vulnerabilities = "".join(
        '<Vulnerability><CVE>' + cve + '</CVE><ProductStatuses>'
        '<Status Type="Fixed">'
        + "".join(f"<ProductID>{p}</ProductID>" for p in packages)
        + '</Status></ProductStatuses></Vulnerability>'
        for cve in cves
    )
    return f"<cvrfdoc{xmlns}><ProductTree/>{vulnerabilities}</cvrfdoc>".encode()


def make_archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:bz2") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def fetch_archive(files):
    payload = make_archive(files)
    with patch("urllib.request.urlopen", return_value=io.BytesIO(payload)) as urlopen:
        result = fetch_suse_backports()
        urlopen.assert_called_once()
        assert urlopen.call_args.kwargs["timeout"] == 60
        assert urlopen.call_args.args[0].full_url.startswith("https://ftp.suse.com/")
    return result


def test_real_suse_cve_version_from_public_advisory():
    """CVE/EVR verified at suse.com/security/cve/CVE-2026-50195.html."""
    data = parse_suse_cvrf(advisory())
    assert data == {"CVE-2026-50195": {"trivy": {"0.71.2-bp157.2.12.1"}}}


def test_one_cve_multiple_packages_and_namespaces():
    data = parse_suse_cvrf(advisory(packages=[
        "openSUSE Leap 16.0:cloudflared-2026.8.2-bp160.1.1",
        "openSUSE Leap 16.0:trivy-0.71.2-160000.1.1",
    ]))
    assert data["CVE-2026-50195"] == {
        "cloudflared": {"2026.8.2-bp160.1.1"},
        "trivy": {"0.71.2-160000.1.1"},
    }


def test_multiple_cves_in_one_advisory_and_no_namespace():
    data = parse_suse_cvrf(advisory(
        cves=("CVE-2026-50195", "CVE-2026-72815"), namespace=False,
    ))
    assert list(data) == ["CVE-2026-50195", "CVE-2026-72815"]


def test_unknown_unfixed_and_no_cve_are_excluded():
    xml = b'''<cvrfdoc><Vulnerability><CVE>CVE-2026-50195</CVE>
       <ProductStatuses><Status Type="Known Affected"><ProductID>
       openSUSE Leap 16.0:trivy-1.0-1.1</ProductID></Status></ProductStatuses>
       </Vulnerability><Vulnerability><ProductStatuses>
       <Status Type="Fixed"><ProductID>openSUSE Leap 16.0:a-1.0-1.1</ProductID>
       </Status></ProductStatuses></Vulnerability></cvrfdoc>'''
    assert parse_suse_cvrf(xml) == {}


def test_reject_incomplete_versions_and_bad_cve():
    data = parse_suse_cvrf(advisory(cves=("NOT-A-CVE",)))
    assert data == {}
    assert _package_fix("openSUSE Leap 16.0:trivy-1.0") is None
    assert _package_fix("Other Linux:trivy-1.0-1.1") is None


def test_product_tree_identifier_resolution():
    xml = b'''<cvrfdoc><ProductTree><FullProductName ProductID="a-1">
        SUSE Linux Enterprise Server 15 SP6:openssl-3.0.0-150600.7.11.1
        </FullProductName></ProductTree><Vulnerability><CVE>CVE-2024-12345</CVE>
        <ProductStatuses><Status Type="Fixed"><ProductID>a-1</ProductID>
        </Status></ProductStatuses></Vulnerability></cvrfdoc>'''
    assert parse_suse_cvrf(xml) == {
        "CVE-2024-12345": {"openssl": {"3.0.0-150600.7.11.1"}}
    }


def test_conflicting_nonfixed_status_for_same_product_is_excluded():
    xml = b'''<cvrfdoc><Vulnerability><CVE>CVE-2024-12345</CVE>
     <ProductStatuses><Status Type="Fixed"><ProductID>openSUSE Leap 16.0:pkg-1.0-1.1</ProductID></Status>
     <Status Type="Known Affected"><ProductID>openSUSE Leap 16.0:pkg-1.0-1.1</ProductID></Status>
     </ProductStatuses></Vulnerability></cvrfdoc>'''
    assert parse_suse_cvrf(xml) == {}


def test_malformed_xml_and_dtd_rejected():
    with pytest.raises(Exception):
        parse_suse_cvrf(b"<cvrfdoc><Vulnerability>")
    with pytest.raises(ValueError, match="DTD"):
        parse_suse_cvrf(b'<!DOCTYPE doc SYSTEM "local.dtd"><doc/>')


def test_multiple_advisories_and_deterministic_merge():
    files = {
        "cvrf-suse-su-2026:2215-1.xml": advisory(),
        "cvrf-opensuse-su-2026:2216-1.xml": advisory(
            cves=("CVE-2026-72815",),
            packages=["openSUSE Leap 16.0:trivy-0.71.2-bp157.2.12.1"],
        ),
    }
    result = fetch_archive(files)
    assert result == {
        "CVE-2026-50195": {"trivy": "0.71.2-bp157.2.12.1"},
        "CVE-2026-72815": {"trivy": "0.71.2-bp157.2.12.1"},
    }


def test_same_version_across_releases_is_kept():
    result = fetch_archive({
        "cvrf-suse-su-2026:1-1.xml": advisory(packages=[
            "SUSE Linux Enterprise Server 15 SP6:trivy-0.71.2-bp157.2.12.1",
            "openSUSE Leap 15.6:trivy-0.71.2-bp157.2.12.1",
        ]),
    })
    assert result["CVE-2026-50195"] == {"trivy": "0.71.2-bp157.2.12.1"}




def test_conflicting_versions_are_omitted_not_overwritten():
    files = {
        "cvrf-suse-su-2026:1-1.xml": advisory(packages=[
            "SUSE Linux Enterprise Server 15 SP6:trivy-0.71.2-bp157.2.12.1",
            "openSUSE Leap 16.0:trivy-0.71.2-160000.1.1",
            "openSUSE Leap 16.0:cloudflared-2026.8.2-bp160.1.1",
        ]),
    }

    with patch("apps.nmap.sources.suse_security.LOGGER.warning") as warning:
        result = fetch_archive(files)

    assert result == {
        "CVE-2026-50195": {
            "cloudflared": "2026.8.2-bp160.1.1"
        }
    }

    warning.assert_called_once()
    assert "conflicting release-specific" in warning.call_args.args[0]
    assert warning.call_args.args[1] == 1



def test_all_conflicts_raise_to_protect_existing_data():
    with pytest.raises(ValueError, match="release-ambiguous"):
        fetch_archive({"cvrf-suse-su-2026:1-1.xml": advisory(packages=[
            "SUSE Linux Enterprise Server 15 SP6:trivy-0.71.2-bp157.2.12.1",
            "openSUSE Leap 16.0:trivy-0.71.2-160000.1.1",
        ])})


def test_archive_empty_and_no_fix_fail():
    with pytest.raises(ValueError, match="no usable"):
        fetch_archive({})
    with pytest.raises(ValueError, match="no usable"):
        fetch_archive({"cvrf-suse-su-2026:1-1.xml": advisory(cves=())})


def test_truncated_or_malformed_xml_archive_fails_not_partial():
    with pytest.raises(Exception):
        fetch_archive({
            "cvrf-suse-su-2026:1-1.xml": advisory(),
            "cvrf-suse-su-2026:2-1.xml": b"<cvrfdoc>",
        })


def test_unrecognized_member_is_ignored():
    result = fetch_archive({
        "LICENSE": b"not xml",
        "cvrf-suse-su-2026:2-1.xml": advisory(),
    })
    assert result["CVE-2026-50195"]["trivy"] == "0.71.2-bp157.2.12.1"


@pytest.mark.parametrize("problem", [
    urllib.error.HTTPError("https://ftp.suse.com", 503, "error", {}, None),
    TimeoutError("timed out"),
    urllib.error.URLError("cannot connect"),
])
def test_network_errors_propagate(problem):
    with patch("urllib.request.urlopen", side_effect=problem):
        with pytest.raises(type(problem)):
            fetch_suse_backports()


def test_reject_oversized_members_and_archive(monkeypatch):
    from apps.nmap.sources import suse_security

    files = {"cvrf-suse-su-2026:1-1.xml": advisory()}
    with monkeypatch.context() as m:
        m.setattr(suse_security, "_MAX_ADVISORY_SIZE", 10)
        with pytest.raises(ValueError, match="advisory too large"):
            fetch_archive(files)
    with monkeypatch.context() as m:
        m.setattr(suse_security, "_MAX_TOTAL_UNCOMPRESSED", 10)
        with pytest.raises(ValueError, match="uncompressed size limit"):
            fetch_archive(files)
    with monkeypatch.context() as m:
        m.setattr(suse_security, "_MAX_ADVISORIES", 0)
        with pytest.raises(ValueError, match="advisory limit"):
            fetch_archive(files)


def test_non_tar_data_is_not_mistaken_for_an_empty_feed():
    with patch("urllib.request.urlopen", return_value=io.BytesIO(b"not a tar archive")):
        with pytest.raises((tarfile.ReadError, OSError, EOFError)):
            fetch_suse_backports()
