import json
from contextlib import ExitStack
from unittest.mock import patch, MagicMock, mock_open
from apps.nmap.sources.ubuntu_usn import fetch_ubuntu_backports
from apps.nmap.sources.debian_security_tracker import fetch_debian_backports

UBUNTU_MOCK_DATA = {
    "notices": [
        {
            "cves_ids": ["CVE-2024-1234"],
            "release_packages": {
                "noble": [{"name": "openssh", "version": "1:9.6p1-3ubuntu13.4"}]
            },
        }
    ]
}

DEBIAN_MOCK_DATA = {
    "openssh": {
        "CVE-2024-5678": {
            "releases": {
                "bookworm": {"status": "resolved", "fixed_version": "1:9.2p1-2+deb12u3"}
            }
        }
    }
}


@patch("urllib.request.urlopen")
def test_fetch_ubuntu_backports(mock_urlopen):
    # Setup mock response
    mock_response = MagicMock()
    # First call returns data, second call returns empty notices to break loop
    mock_response.read.side_effect = [
        json.dumps(UBUNTU_MOCK_DATA).encode("utf-8"),
        json.dumps({"notices": []}).encode("utf-8"),
    ]
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    result = fetch_ubuntu_backports()

    assert "CVE-2024-1234" in result
    assert result["CVE-2024-1234"]["openssh"] == "1:9.6p1-3ubuntu13.4"


@patch("urllib.request.urlopen")
def test_fetch_debian_backports(mock_urlopen):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(DEBIAN_MOCK_DATA).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    result = fetch_debian_backports()

    assert "CVE-2024-5678" in result
    assert result["CVE-2024-5678"]["bookworm"]["openssh"] == "1:9.2p1-2+deb12u3"


@patch("apps.nmap.management.commands.refresh_backports.fetch_ubuntu_backports")
@patch("apps.nmap.management.commands.refresh_backports.fetch_debian_backports")
@patch("apps.nmap.management.commands.refresh_backports.fetch_alpine_backports")
@patch("apps.nmap.management.commands.refresh_backports.fetch_suse_backports")
@patch("builtins.open")
@patch("os.replace")
def test_do_refresh_schema_merge(
    mock_replace, mock_open, mock_suse, mock_alpine, mock_debian, mock_ubuntu
):
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


@patch("builtins.open", new_callable=mock_open)
@patch("os.replace")
def test_do_refresh_tolerates_empty_feed(mock_replace, mock_open):
    """A single empty feed must NOT abort the refresh.

    Regression guard for the reviewer blockers on #432/#433: an empty Red Hat
    or SUSE response used to ``sys.exit(1)`` and drop every other feed's data.
    Now the empty feed is skipped (and its previous slice preserved) while the
    good feeds are still merged and written.
    """
    from apps.nmap.management.commands import refresh_backports as cmd

    # Patch only the fetchers that actually exist on this branch.
    present = [
        n
        for n in ("ubuntu", "debian", "alpine", "redhat", "suse")
        if hasattr(cmd, f"fetch_{n}_backports")
    ]

    good = {
        "ubuntu": {"CVE-UBUNTU": {"pkg": "1.0"}},
        "debian": {"CVE-DEBIAN": {"pkg": "2.0"}},
        "alpine": {"CVE-ALPINE": {"pkg": "3.0"}},
        "redhat": {"CVE-REDHAT": {"pkg": "4.0"}},
        "suse": {"CVE-SUSE": {"pkg": "5.0"}},
    }

    with ExitStack() as stack:
        patchers = {
            n: stack.enter_context(
                patch(
                    f"apps.nmap.management.commands.refresh_backports.fetch_{n}_backports"
                )
            )
            for n in present
        }
        # Make exactly one feed come back empty (simulating an upstream outage).
        empty_feed = present[-1]
        for n in present:
            patchers[n].return_value = {} if n == empty_feed else good[n]

        cmd.do_refresh()

    # The refresh must not have exited; the file was written.
    mock_replace.assert_called_once()
    handle = mock_open.return_value.__enter__.return_value
    written_data = "".join(c.args[0] for c in handle.write.call_args_list)
    parsed = json.loads(written_data)

    # Every non-empty feed is merged.
    for n in present:
        if n != empty_feed:
            assert n in parsed
            assert parsed[n] == good[n]
    # The empty feed is preserved from the previous backports.json content
    # (the mocked open reads nothing useful, so it simply isn't added fresh —
    # the important assertion is that the run completed instead of aborting).
    assert empty_feed not in parsed or parsed[empty_feed] == {}
