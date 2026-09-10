import json
from unittest.mock import patch, MagicMock

from apps.nmap.sources.redhat_security import fetch_redhat_backports

# Fixture: one CVE with a Fixed package, one with "Will not fix", one "Affected".
REDHAT_MOCK_DATA = [
    {
        "CVE": "CVE-2024-1234",
        "affected_packages": [
            {
                "package_name": "openssh",
                "package_state": "Fixed",
                "fixed_in": "8.0p1-1.el9",
            },
            {
                "package_name": "openssl",
                "package_state": "Fixed",
                "fixed_in": ["3.0.7-1.el9", "3.0.7-2.el9"],
            },
        ],
    },
    {
        "CVE": "CVE-2024-5678",
        "affected_packages": [
            {
                "package_name": "kernel",
                "package_state": "Will not fix",
                "fixed_in": "0:5.14.0-1.el9",
            }
        ],
    },
    {
        "CVE": "CVE-2024-9999",
        "affected_packages": [
            {
                "package_name": "bash",
                "package_state": "Affected",
                "fixed_in": "0:5.1.8-1.el9",
            }
        ],
    },
]


@patch("urllib.request.urlopen")
def test_fetch_redhat_backports(mock_urlopen):
    mock_response = MagicMock()
    # One page with data, then an empty list to stop paging.
    mock_response.read.side_effect = [
        json.dumps(REDHAT_MOCK_DATA).encode("utf-8"),
        json.dumps([]).encode("utf-8"),
    ]
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    result = fetch_redhat_backports()

    # Happy path: fixed package present.
    assert "CVE-2024-1234" in result
    assert result["CVE-2024-1234"]["openssh"] == "8.0p1-1.el9"
    # Multiple fixed_in values: the most specific (last) is kept.
    assert result["CVE-2024-1234"]["openssl"] == "3.0.7-2.el9"

    # "Will not fix" and "Affected" states must be excluded.
    assert "CVE-2024-5678" not in result
    assert "CVE-2024-9999" not in result


@patch("urllib.request.urlopen")
def test_fetch_redhat_backports_handles_malformed_page(mock_urlopen):
    # Malformed JSON on the first page must not crash the parser: it logs
    # and stops paging, returning whatever (here: nothing).
    mock_response = MagicMock()
    mock_response.read.side_effect = [b"not-json", b"[]"]
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    result = fetch_redhat_backports()
    assert result == {}
