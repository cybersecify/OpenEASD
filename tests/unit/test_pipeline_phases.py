"""Tests that tool_meta phase numbers match the intended pipeline order."""
import pytest


def test_phase_order():
    """Non-web tools (7) must run before httpx (8) and web tools (9)."""
    from apps.core.workflows.registry import get_tool_phases
    phases = get_tool_phases()

    assert phases["httpx"] == 8,           f"httpx: expected 8, got {phases['httpx']}"
    assert phases["nuclei_network"] == 7,  f"nuclei_network: expected 7, got {phases['nuclei_network']}"
    assert phases["nuclei"] == 9,          f"nuclei: expected 9, got {phases['nuclei']}"
    assert phases["web_checker"] == 9,     f"web_checker: expected 9, got {phases['web_checker']}"

    # Non-web tools must all be before httpx
    assert phases["nmap"] < phases["httpx"],          "nmap must run before httpx"
    assert phases["tls_checker"] < phases["httpx"],   "tls_checker must run before httpx"
    assert phases["ssh_checker"] < phases["httpx"],   "ssh_checker must run before httpx"
    assert phases["nuclei_network"] < phases["httpx"],"nuclei_network must run before httpx"

    # Web tools must run after httpx
    assert phases["nuclei"] > phases["httpx"],        "nuclei must run after httpx"
    assert phases["web_checker"] > phases["httpx"],   "web_checker must run after httpx"
