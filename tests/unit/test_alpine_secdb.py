import json
import urllib.request
import pytest
from unittest.mock import patch, MagicMock
from apps.nmap.sources.alpine_secdb import fetch_alpine_backports

@pytest.fixture
def mock_alpine_json():
    return json.dumps({
        "packages": [
            {
                "pkg": {
                    "name": "aom",
                    "secfixes": {
                        "3.1.1-r0": ["CVE-2021-30473", "CVE-2021-30474"],
                        "3.9.1-r0": ["CVE-2024-5171"]
                    }
                }
            }
        ]
    }).encode('utf-8')

@pytest.fixture
def mock_malformed_json():
    return b"invalid json data"

@patch('urllib.request.urlopen')
def test_fetch_alpine_backports_happy_path(mock_urlopen, mock_alpine_json):
    # Setup mock
    mock_response = MagicMock()
    mock_response.read.return_value = mock_alpine_json
    mock_urlopen.return_value.__enter__.return_value = mock_response

    backports = fetch_alpine_backports()
    
    # Assert
    assert "CVE-2021-30473" in backports
    assert backports["CVE-2021-30473"]["aom"] == "3.1.1-r0"
    
    assert "CVE-2024-5171" in backports
    assert backports["CVE-2024-5171"]["aom"] == "3.9.1-r0"

    # Expect urlopen to be called for branches x repos (3 x 2 = 6 times)
    assert mock_urlopen.call_count == 6

@patch('urllib.request.urlopen')
def test_fetch_alpine_backports_malformed(mock_urlopen, mock_malformed_json):
    # Setup mock to return invalid JSON
    mock_response = MagicMock()
    mock_response.read.return_value = mock_malformed_json
    mock_urlopen.return_value.__enter__.return_value = mock_response

    backports = fetch_alpine_backports()
    
    # Should not crash and return empty dictionary since all fetches fail json parsing
    assert backports == {}
    assert mock_urlopen.call_count == 6

@patch('urllib.request.urlopen')
def test_fetch_alpine_backports_network_error(mock_urlopen):
    # Setup mock to raise exception
    mock_urlopen.side_effect = Exception("Network timeout")

    backports = fetch_alpine_backports()
    
    # Should handle error gracefully and return empty dict
    assert backports == {}
    assert mock_urlopen.call_count == 6
