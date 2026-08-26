"""Unit tests for apps/nmap/backports — Debian/Ubuntu version compare + backport demotion.

The backport engine is what stops a version-based CVE match from screaming
CRITICAL on a distro package that already carries the security fix as a backport
(same upstream version string, patched build). These tests exercise the two
pieces directly: the version comparator and the check_backport orchestration,
including the "protocol 2.0" false-positive guard that used to capture the word
"protocol" as a fake distro version.
"""

from unittest.mock import patch

from apps.nmap.backports import check_backport, compare_debian_versions


# ---------------------------------------------------------------------------
# compare_debian_versions
# ---------------------------------------------------------------------------

class TestCompareDebianVersions:
    def test_ubuntu_patch_bump_greater(self):
        assert compare_debian_versions("3ubuntu13.4", "3ubuntu13.3") == 1

    def test_ubuntu_patch_bump_less(self):
        assert compare_debian_versions("3ubuntu13.3", "3ubuntu13.4") == -1

    def test_equal_versions(self):
        assert compare_debian_versions("3ubuntu13.4", "3ubuntu13.4") == 0

    def test_debian_deb_suffix_greater(self):
        assert compare_debian_versions("5+deb11u3", "5+deb11u2") == 1

    def test_debian_deb_suffix_less(self):
        assert compare_debian_versions("5+deb11u2", "5+deb11u3") == -1

    def test_mixed_numeric_and_string_segments(self):
        # Different lead numbers decide before any string segment matters.
        assert compare_debian_versions("10ubuntu1", "9ubuntu1") == 1
        assert compare_debian_versions("9ubuntu1", "10ubuntu1") == -1

    def test_longer_version_is_greater_when_prefix_equal(self):
        # "1.2.3" is a superset of "1.2" — the extra segment breaks the tie.
        assert compare_debian_versions("1.2.3", "1.2") == 1
        assert compare_debian_versions("1.2", "1.2.3") == -1


# ---------------------------------------------------------------------------
# check_backport
# ---------------------------------------------------------------------------

_BACKPORTS = {
    "ubuntu": {"CVE-2024-6387": {"openssh": "3ubuntu13.3"}},
    "debian": {"CVE-2024-6387": {"openssh": "5+deb11u2"}},
}


class TestCheckBackport:
    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_ubuntu_installed_at_or_above_fix_is_backported(self):
        result = check_backport(
            "openssh", "OpenSSH 9.6p1 Ubuntu-3ubuntu13.4", "CVE-2024-6387"
        )
        assert result == {"backport_applied": True, "first_fixed_in": "3ubuntu13.3"}

    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_ubuntu_installed_below_fix_is_not_backported(self):
        # Installed 3ubuntu13.2 predates the fixed 3ubuntu13.3 → still vulnerable.
        assert check_backport(
            "openssh", "OpenSSH 9.6p1 Ubuntu-3ubuntu13.2", "CVE-2024-6387"
        ) is None

    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_debian_deb_suffix_backported(self):
        result = check_backport(
            "openssh", "OpenSSH 8.4p1 Debian-5+deb11u3", "CVE-2024-6387"
        )
        assert result == {"backport_applied": True, "first_fixed_in": "5+deb11u2"}

    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_ubuntu_space_semicolon_form_still_matched(self):
        # nmap sometimes emits "Ubuntu Linux; 3ubuntu13.4" instead of "Ubuntu-...".
        result = check_backport(
            "openssh", "OpenSSH 9.6p1 Ubuntu Linux; 3ubuntu13.4", "CVE-2024-6387"
        )
        assert result == {"backport_applied": True, "first_fixed_in": "3ubuntu13.3"}

    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_protocol_2_0_is_not_read_as_a_distro_version(self):
        # "Ubuntu Linux; protocol 2.0" carries NO distro build suffix. The regex
        # must not capture "protocol"/"2.0" as a version and falsely backport.
        assert check_backport(
            "openssh", "OpenSSH 9.6p1 Ubuntu Linux; protocol 2.0", "CVE-2024-6387"
        ) is None

    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_unknown_cve_returns_none(self):
        assert check_backport(
            "openssh", "OpenSSH 9.6p1 Ubuntu-3ubuntu13.4", "CVE-9999-0000"
        ) is None

    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_product_not_in_cve_entry_returns_none(self):
        # CVE is known for the distro but not for this product name.
        assert check_backport(
            "nginx", "nginx 1.18 Ubuntu-3ubuntu13.4", "CVE-2024-6387"
        ) is None

    def test_empty_product_or_version_returns_none(self):
        assert check_backport("", "OpenSSH 9.6p1 Ubuntu-3ubuntu13.4", "CVE-2024-6387") is None
        assert check_backport("openssh", "", "CVE-2024-6387") is None

    @patch("apps.nmap.backports.BACKPORTS", _BACKPORTS)
    def test_non_distro_version_string_returns_none(self):
        # A generic upstream banner with no ubuntu/debian marker.
        assert check_backport(
            "openssh", "OpenSSH 9.6p1", "CVE-2024-6387"
        ) is None
