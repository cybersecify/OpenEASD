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
    # First call returns data, second call returns empty notices to break loop
    mock_response.read.side_effect = [
        json.dumps(UBUNTU_MOCK_DATA).encode('utf-8'),
        json.dumps({"notices": []}).encode('utf-8')
    ]
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
    assert result["CVE-2024-5678"]["bookworm"]["openssh"] == "1:9.2p1-2+deb12u3"

@patch('apps.nmap.management.commands.refresh_backports.fetch_ubuntu_backports')
@patch('apps.nmap.management.commands.refresh_backports.fetch_debian_backports')
@patch('apps.nmap.management.commands.refresh_backports.fetch_alpine_backports')
@patch('apps.nmap.management.commands.refresh_backports.fetch_suse_backports')
@patch('builtins.open')
@patch('os.replace')
def test_do_refresh_schema_merge(mock_replace, mock_open, mock_suse, mock_alpine, mock_debian, mock_ubuntu):
    mock_ubuntu.return_value = {"CVE-UBUNTU": {"pkg": "1.0"}}
    mock_debian.return_value = {"CVE-DEBIAN": {"pkg": "2.0"}}
    mock_alpine.return_value = {"CVE-ALPINE": {"pkg": "3.0"}}
    mock_suse.return_value = {"CVE-SUSE": {"pkg": "4.0"}}

    # Import the command locally to avoid executing it on import if __main__ is not protected
    from apps.nmap.management.commands.refresh_backports import do_refresh

    do_refresh()

    mock_ubuntu.assert_called_once()
    mock_debian.assert_called_once()
    mock_alpine.assert_called_once()
    mock_suse.assert_called_once()
    mock_open.assert_called_once()

    # Extract the JSON string that was written
    handle = mock_open.return_value.__enter__.return_value
    written_data = "".join(call.args[0] for call in handle.write.call_args_list)
    parsed_json = json.loads(written_data)

    assert "ubuntu" in parsed_json
    assert "debian" in parsed_json
    assert "alpine" in parsed_json
    assert "suse" in parsed_json
    assert parsed_json["ubuntu"]["CVE-UBUNTU"]["pkg"] == "1.0"
    assert parsed_json["debian"]["CVE-DEBIAN"]["pkg"] == "2.0"
    assert parsed_json["alpine"]["CVE-ALPINE"]["pkg"] == "3.0"
    assert parsed_json["suse"]["CVE-SUSE"]["pkg"] == "4.0"


def test_do_refresh_atomic_write_includes_suse(tmp_path, monkeypatch):
    """Check the real replace/write path instead of only mocking os.replace."""
    from apps.nmap.management.commands import refresh_backports as refresh

    target_dir = tmp_path / "apps" / "nmap"
    target_dir.mkdir(parents=True)
    target = target_dir / "backports.json"
    target.write_text('{"previous": true}', encoding="utf-8")
    monkeypatch.setattr(
        refresh, "__file__", str(target_dir / "management" / "commands" / "refresh_backports.py")
    )
    monkeypatch.setattr(refresh, "fetch_ubuntu_backports", lambda: {"CVE-U": {"p": "1"}})
    monkeypatch.setattr(refresh, "fetch_debian_backports", lambda: {"CVE-D": {"p": "2"}})
    monkeypatch.setattr(refresh, "fetch_alpine_backports", lambda: {"CVE-A": {"p": "3"}})
    monkeypatch.setattr(refresh, "fetch_suse_backports", lambda: {"CVE-S": {"p": "4"}})

    refresh.do_refresh()
    assert json.loads(target.read_text(encoding="utf-8")) == {
        "ubuntu": {"CVE-U": {"p": "1"}},
        "debian": {"CVE-D": {"p": "2"}},
        "alpine": {"CVE-A": {"p": "3"}},
        "suse": {"CVE-S": {"p": "4"}},
    }
    assert not target.with_suffix(".json.tmp").exists()


def test_do_refresh_empty_suse_does_not_replace(tmp_path, monkeypatch):
    from apps.nmap.management.commands import refresh_backports as refresh

    target_dir = tmp_path / "apps" / "nmap"
    target_dir.mkdir(parents=True)
    target = target_dir / "backports.json"
    target.write_text("old data", encoding="utf-8")
    monkeypatch.setattr(
        refresh, "__file__", str(target_dir / "management" / "commands" / "refresh_backports.py")
    )
    monkeypatch.setattr(refresh, "fetch_ubuntu_backports", lambda: {"CVE-U": {}})
    monkeypatch.setattr(refresh, "fetch_debian_backports", lambda: {"CVE-D": {}})
    monkeypatch.setattr(refresh, "fetch_alpine_backports", lambda: {"CVE-A": {}})
    monkeypatch.setattr(refresh, "fetch_suse_backports", lambda: {})

    import pytest
    with pytest.raises(SystemExit) as error:
        refresh.do_refresh()
    assert error.value.code == 1
    assert target.read_text(encoding="utf-8") == "old data"
    assert not target.with_suffix(".json.tmp").exists()


def test_do_refresh_failed_suse_does_not_replace(tmp_path, monkeypatch):
    from apps.nmap.management.commands import refresh_backports as refresh

    target_dir = tmp_path / "apps" / "nmap"
    target_dir.mkdir(parents=True)
    target = target_dir / "backports.json"
    target.write_text("old data", encoding="utf-8")
    monkeypatch.setattr(
        refresh, "__file__", str(target_dir / "management" / "commands" / "refresh_backports.py")
    )
    monkeypatch.setattr(refresh, "fetch_ubuntu_backports", lambda: {"CVE-U": {}})
    monkeypatch.setattr(refresh, "fetch_debian_backports", lambda: {"CVE-D": {}})
    monkeypatch.setattr(refresh, "fetch_alpine_backports", lambda: {"CVE-A": {}})

    def failed_fetch():
        raise TimeoutError("SUSE feed timeout")

    monkeypatch.setattr(refresh, "fetch_suse_backports", failed_fetch)
    import pytest
    with pytest.raises(TimeoutError, match="SUSE feed timeout"):
        refresh.do_refresh()
    assert target.read_text(encoding="utf-8") == "old data"
    assert not target.with_suffix(".json.tmp").exists()
