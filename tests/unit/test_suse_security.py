from unittest.mock import patch

from apps.nmap.sources.suse_security import (
    fetch_suse_backports,
    parse_suse_cvrf,
    _split_product,
)

SUSE_FIXTURE_XML = open("/tmp/suse_fixture.xml").read()


def test_split_product():
    # family prefix is dropped; name is everything before the last dash,
    # version is the remainder.
    assert _split_product("SUSE Liberty Linux 7 LTSS:httpd-2.4.6-99.el7_9.2") == (
        "httpd",
        "2.4.6-99.el7_9.2",
    )
    # no version digit -> rejected
    assert _split_product("not-a-real-product") == ("", "")
    assert _split_product("") == ("", "")


def test_parse_suse_cvrf_happy_path():
    result = parse_suse_cvrf(SUSE_FIXTURE_XML)
    # Real CVE-2020-35452 mapped from the fixture, with real fixed builds.
    assert "CVE-2020-35452" in result
    assert result["CVE-2020-35452"]["httpd"] == "2.4.6-99.el7_9.2"
    assert result["CVE-2020-35452"]["mod_ssl"] == "2.4.6-99.el7_9.2"


def test_parse_suse_cvrf_malformed_does_not_crash():
    assert parse_suse_cvrf("not-xml-at-all") == {}
    assert parse_suse_cvrf("<cvrfdoc></cvrfdoc>") == {}


@patch("apps.nmap.sources.suse_security.urllib.request.urlopen")
def test_fetch_suse_backports(mock_urlopen):
    # index page -> one xml doc; doc fetch -> the fixture.
    index_html = '<a href="cvrf-esba-2024%3A0591.xml">x</a>'
    doc_xml = SUSE_FIXTURE_XML

    class _Resp:
        def __init__(self, body):
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._body.encode("utf-8")

    def fake_open(req, timeout=None):
        url = str(req.full_url)
        body = index_html if url.endswith("/cvrf/") else doc_xml
        return _Resp(body)

    mock_urlopen.side_effect = fake_open

    result = fetch_suse_backports()
    assert "CVE-2020-35452" in result
    assert result["CVE-2020-35452"]["httpd"] == "2.4.6-99.el7_9.2"
