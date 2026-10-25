"""Unit tests for apps/nmap/sources/redhat_security.

The fixture in tests/fixtures/redhat_cve_list.json is a verbatim slice of the
live feed (records captured from
https://access.redhat.com/hydra/rest/securitydata/cve.json) so the parser is
exercised against the shape the API really returns:

  * `affected_packages` is a list of Name-Version-Release *strings* — not dicts
    and with no `fixed_in` field;
  * `package_state` is a separate, version-less top-level field (null here);
  * container and module builds share `affected_packages` with rpm builds.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from apps.nmap.sources.redhat_security import (
    fetch_redhat_backports,
    parse_fixed_build,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "redhat_cve_list.json"


def _load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _mock_feed(mock_urlopen, pages):
    mock_response = MagicMock()
    mock_response.read.side_effect = [p.encode("utf-8") for p in pages]
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response


# ---------------------------------------------------------------------------
# parse_fixed_build
# ---------------------------------------------------------------------------


def test_parse_fixed_build_strips_name_and_epoch():
    assert parse_fixed_build("openssh-0:8.7p1-38.el9_4.1") == (
        "openssh",
        "8.7p1-38.el9_4.1",
    )
    # multi-digit epoch, name with dashes
    assert parse_fixed_build("qemu-kvm-17:9.0.0-10.el9_5.3") == (
        "qemu-kvm",
        "9.0.0-10.el9_5.3",
    )


def test_parse_fixed_build_rejects_non_rpm_builds():
    # container build, module stream, non-RHEL build and CoreOS image build
    for entry in (
        "io.quarkus/quarkus-kubernetes-deployment:3.2.11.Final-redhat-00001",
        "virt:rhel-8100020240314161907.e155f54d",
        "openssl3-main-3.5.8-0.1.hum1",
        "rhcos-416.94.202407081958-0",
    ):
        assert parse_fixed_build(entry) is None


def test_parse_fixed_build_rejects_non_strings():
    assert parse_fixed_build({"package_name": "openssh"}) is None
    assert parse_fixed_build(None) is None


# ---------------------------------------------------------------------------
# fetch_redhat_backports
# ---------------------------------------------------------------------------


@patch("urllib.request.urlopen")
def test_fetch_redhat_backports(mock_urlopen):
    # One page of real feed data, then an empty list to stop paging.
    _mock_feed(mock_urlopen, [json.dumps(_load_fixture()), "[]"])

    result = fetch_redhat_backports()

    # Happy path: the highest fixed build of the package is kept.
    assert result["CVE-2024-6387"]["openssh"] == "8.7p1-38.el9_4.1"
    # Epoch is stripped so the value compares against a bare banner version.
    assert result["CVE-2023-6693"]["qemu-kvm"] == "9.0.0-10.el9_5.3"
    # el8-derived builds are kept too.
    assert result["CVE-2024-21647"]["rubygem-puma"] == "6.4.2-1.el8sat"
    assert result["CVE-2024-22047"]["rubygem-audited"] == "5.4.2-1.el8sat"

    # CoreOS builds carry no .elN release tag — they are not rpm builds.
    assert "rhcos" not in result["CVE-2024-6387"]
    # Module streams are not rpm builds either.
    assert "virt" not in result["CVE-2023-6693"]


@patch("urllib.request.urlopen")
def test_fetch_redhat_backports_skips_cves_without_a_fixed_build(mock_urlopen):
    _mock_feed(mock_urlopen, [json.dumps(_load_fixture()), "[]"])

    result = fetch_redhat_backports()

    # CVE-2024-0582 has no fix published (empty affected_packages) and
    # CVE-2024-1979 only ships a container build — neither can demote anything.
    assert "CVE-2024-0582" not in result
    assert "CVE-2024-1979" not in result


@patch("urllib.request.urlopen")
def test_fetch_redhat_backports_handles_malformed_page(mock_urlopen):
    # Malformed JSON on the first page must not crash the parser: it logs
    # and stops paging, returning whatever (here: nothing).
    _mock_feed(mock_urlopen, ["not-json", "[]"])

    assert fetch_redhat_backports() == {}
