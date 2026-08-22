"""Unit tests for the update-available check (apps/core/api/update_check.py)."""

from unittest.mock import patch, MagicMock

import pytest
import requests
from django.core.cache import cache

from apps.core.api import update_check as uc


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()
    yield
    cache.clear()


class TestParseVersion:
    def test_plain_dotted(self):
        assert uc._parse_version("0.10.0") == (0, 10, 0)

    def test_v_prefixed(self):
        assert uc._parse_version("v1.2.3") == (1, 2, 3)

    @pytest.mark.parametrize("bad", ["dev", "unknown", "", None, "DEV"])
    def test_placeholders_are_none(self, bad):
        assert uc._parse_version(bad) is None

    def test_non_numeric_is_none(self):
        assert uc._parse_version("v1.2.x") is None


class TestIsUpdateAvailable:
    def test_newer_latest_true(self):
        assert uc.is_update_available("0.10.0", "0.11.0") is True

    def test_equal_false(self):
        assert uc.is_update_available("0.10.0", "0.10.0") is False

    def test_older_latest_false(self):
        assert uc.is_update_available("0.11.0", "0.10.0") is False

    def test_dev_current_never_available(self):
        # A local/dev build can't be meaningfully compared -> never nag.
        assert uc.is_update_available("dev", "0.10.0") is False

    def test_unparseable_latest_false(self):
        assert uc.is_update_available("0.10.0", None) is False


class TestGetLatestRelease:
    def _resp(self, tag="v0.11.0", url="https://gh/rel"):
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = {"tag_name": tag, "html_url": url}
        return m

    def test_happy_path_strips_v(self):
        with patch("apps.core.api.update_check.requests.get", return_value=self._resp()) as g:
            out = uc.get_latest_release()
        assert out == {"version": "0.11.0", "url": "https://gh/rel"}
        g.assert_called_once()

    def test_result_is_cached(self):
        with patch("apps.core.api.update_check.requests.get", return_value=self._resp()) as g:
            uc.get_latest_release()
            uc.get_latest_release()  # second call must hit cache, not network
        g.assert_called_once()

    def test_timeout_returns_none(self):
        with patch("apps.core.api.update_check.requests.get",
                   side_effect=requests.Timeout("slow")):
            assert uc.get_latest_release() is None

    def test_http_error_returns_none(self):
        bad = MagicMock()
        bad.raise_for_status.side_effect = requests.HTTPError("500")
        with patch("apps.core.api.update_check.requests.get", return_value=bad):
            assert uc.get_latest_release() is None

    def test_missing_tag_returns_none(self):
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = {"html_url": "x"}
        with patch("apps.core.api.update_check.requests.get", return_value=m):
            assert uc.get_latest_release() is None

    def test_failure_is_cached_briefly(self):
        with patch("apps.core.api.update_check.requests.get",
                   side_effect=requests.Timeout("slow")) as g:
            uc.get_latest_release()
            uc.get_latest_release()  # cached failure -> no second network call
        g.assert_called_once()


class TestCheckForUpdate:
    def test_shape_when_behind(self, settings):
        settings.OPENEASD_VERSION = "0.10.0"
        with patch("apps.core.api.update_check.get_latest_release",
                   return_value={"version": "0.11.0", "url": "https://gh/rel"}):
            out = uc.check_for_update()
        assert out == {
            "current_version": "0.10.0",
            "latest_version": "0.11.0",
            "update_available": True,
            "release_url": "https://gh/rel",
        }

    def test_shape_when_up_to_date(self, settings):
        settings.OPENEASD_VERSION = "0.11.0"
        with patch("apps.core.api.update_check.get_latest_release",
                   return_value={"version": "0.11.0", "url": "https://gh/rel"}):
            out = uc.check_for_update()
        assert out["update_available"] is False

    def test_graceful_when_github_down(self, settings):
        settings.OPENEASD_VERSION = "0.10.0"
        with patch("apps.core.api.update_check.get_latest_release", return_value=None):
            out = uc.check_for_update()
        assert out["latest_version"] is None
        assert out["update_available"] is False
        assert out["release_url"] is None
