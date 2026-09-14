"""Unit tests for apps/nmap/sources/suse_security.

The fixtures in tests/fixtures/suse-cvrf-*.xml are documents downloaded from
https://ftp.suse.com/pub/projects/security/cvrf/ — they are parsed verbatim so
the splitter runs against SUSE's real package strings rather than the
RHEL-style ones the previous fixture used.
"""

from pathlib import Path
from unittest.mock import patch

from apps.nmap.sources.suse_security import (
    _sort_newest_first,
    _split_product,
    fetch_suse_backports,
    parse_suse_cvrf,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
LEAP_DOC = (FIXTURES / "suse-cvrf-opensuse-leap.xml").read_text(encoding="utf-8")
SLES_DOC = (FIXTURES / "suse-cvrf-sles.xml").read_text(encoding="utf-8")


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# _split_product
# ---------------------------------------------------------------------------


def test_split_product_reads_real_suse_nvr():
    # Release is a plain dotted number — no .elN tag to key on.
    assert _split_product("openSUSE Leap 16.0:jq-1.7.1-160000.5.1") == (
        "jq",
        "1.7.1-160000.5.1",
    )
    assert _split_product("apache2-2.4.51-150000.15.35.1") == (
        "apache2",
        "2.4.51-150000.15.35.1",
    )


def test_split_product_keeps_hyphenated_names_intact():
    # Hyphenated package names must not be trimmed to the first dash.
    assert _split_product(
        "SUSE Linux Enterprise Module for Public Cloud 15 SP5:"
        "python311-sqlparse-0.4.4-150400.6.19.1"
    ) == ("python311-sqlparse", "0.4.4-150400.6.19.1")
    assert _split_product(
        "SUSE Linux Enterprise Desktop 12 SP1:libqt4-32bit-4.8.6-7.1"
    ) == ("libqt4-32bit", "4.8.6-7.1")


def test_split_product_rejects_non_packages():
    # A product name with no N-V-R, and a string with no version at all.
    assert _split_product("SUSE Linux Enterprise Server 12") == ("", "")
    assert _split_product("not-a-real-product") == ("", "")
    assert _split_product("") == ("", "")


# ---------------------------------------------------------------------------
# parse_suse_cvrf — against downloaded documents
# ---------------------------------------------------------------------------


def test_parse_real_opensuse_leap_document():
    result = parse_suse_cvrf(LEAP_DOC)

    assert result["CVE-2026-43895"]["jq"] == "1.7.1-160000.5.1"
    assert result["CVE-2026-43895"]["libjq1"] == "1.7.1-160000.5.1"
    # both CVEs in the document are covered by the same fixed build
    assert result["CVE-2026-47770"]["libjq-devel"] == "1.7.1-160000.5.1"


def test_parse_real_sles_document():
    result = parse_suse_cvrf(SLES_DOC)

    assert result["CVE-2026-84305"]["python311-sqlparse"] == "0.4.4-150400.6.19.1"


def test_malformed_xml_returns_empty():
    assert parse_suse_cvrf("not xml at all") == {}


def test_dtd_bearing_document_is_rejected_not_raised():
    # defusedxml raises DefusedXmlException for an entity-bearing DTD; the
    # parser must swallow it and return {} instead of aborting the refresh.
    dtd_doc = """<?xml version="1.0"?>
<!DOCTYPE cvrfdoc [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<cvrfdoc xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf-1.1">
  <Vulnerability><CVE>CVE-2026-00001</CVE></Vulnerability>
</cvrfdoc>"""
    assert parse_suse_cvrf(dtd_doc) == {}


# ---------------------------------------------------------------------------
# fetch_suse_backports
# ---------------------------------------------------------------------------


def test_one_bad_document_does_not_abort_the_run():
    index = b'<a href="bad.xml">bad</a><a href="sles.xml">sles</a>'

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = [
            _FakeResponse(index),
            OSError("connection reset"),
            _FakeResponse(SLES_DOC.encode("utf-8")),
        ]
        result = fetch_suse_backports()

    assert result["CVE-2026-84305"]["python311-sqlparse"] == "0.4.4-150400.6.19.1"


def test_documents_are_sorted_newest_first():
    docs = [
        "cvrf-suse-su-2019%3A0001-1.xml",
        "cvrf-suse-su-403.xml",
        "cvrf-suse-su-2026%3A4109-1.xml",
    ]
    assert _sort_newest_first(docs) == [
        "cvrf-suse-su-2026%3A4109-1.xml",
        "cvrf-suse-su-2019%3A0001-1.xml",
        "cvrf-suse-su-403.xml",
    ]
