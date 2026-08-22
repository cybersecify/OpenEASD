"""Tests for the Go-tool memory-env helper (apps/core/workflows/proc_env.py)."""

from apps.core.workflows.proc_env import go_memory_env


class TestGoMemoryEnv:
    def test_sets_gomemlimit_and_gogc_when_configured(self, settings):
        settings.NUCLEI_GOMEMLIMIT = "600MiB"
        env = go_memory_env()
        assert env["GOMEMLIMIT"] == "600MiB"
        assert env["GOGC"] == "50"

    def test_unchanged_when_no_limit(self, settings):
        settings.NUCLEI_GOMEMLIMIT = ""
        env = go_memory_env()
        assert "GOMEMLIMIT" not in env

    def test_preserves_existing_environment(self, settings, monkeypatch):
        settings.NUCLEI_GOMEMLIMIT = "600MiB"
        monkeypatch.setenv("PATH", "/custom/path")
        env = go_memory_env()
        assert env["PATH"] == "/custom/path"  # inherits real env, just adds limits

    def test_does_not_clobber_preset_gogc(self, settings, monkeypatch):
        settings.NUCLEI_GOMEMLIMIT = "600MiB"
        monkeypatch.setenv("GOGC", "off")
        env = go_memory_env()
        assert env["GOGC"] == "off"  # setdefault leaves an explicit value alone
