import pytest
import json
from unittest.mock import patch, MagicMock
from apps.nmap.sources.ubuntu_usn import fetch_ubuntu_backports
from apps.nmap.sources.debian_security_tracker import fetch_debian_backports

UBUNTU_MOCK_DATA = {
    "notices": [
        {
            "cves_ids": ["CVE-2024-1234"],
            "release_packages": {
                "noble": [
                    {
                        "name": "openssh",
                        "version": "1:9.6p1-3ubuntu13.4"
                    }
                ]
            }
        }
    ]
}

DEBIAN_MOCK_DATA = {
    "openssh": {
        "CVE-2024-5678": {
            "releases": {
                "bookworm": {
                    "status": "resolved",
                    "fixed_version": "1:9.2p1-2+deb12u3"
                }
            }
        }
    }
}

@patch('urllib.request.urlopen')
def test_fetch_ubuntu_backports(mock_urlopen):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(UBUNTU_MOCK_DATA).encode('utf-8')
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    result = fetch_ubuntu_backports()

    assert "CVE-2024-1234" in result
    assert result["CVE-2024-1234"]["openssh"] == "1:9.6p1-3ubuntu13.4"

@patch('urllib.request.urlopen')
def test_fetch_debian_backports(mock_urlopen):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(DEBIAN_MOCK_DATA).encode('utf-8')
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    result = fetch_debian_backports()

    assert "CVE-2024-5678" in result
    assert result["CVE-2024-5678"]["openssh"] == "1:9.2p1-2+deb12u3"
