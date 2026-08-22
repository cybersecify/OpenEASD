"""Subprocess environment helpers for tool runners."""

import os

from django.conf import settings


def go_memory_env():
    """Env dict for memory-hungry Go tools (nuclei / nuclei_network).

    Starts from the current environment and, when the resource profile sets a
    soft ceiling (``settings.NUCLEI_GOMEMLIMIT``), adds ``GOMEMLIMIT`` + a lower
    ``GOGC`` so the Go runtime GCs aggressively instead of letting RSS balloon
    into swap and freezing a small host. When no limit is configured (balanced/
    high profiles) the env is returned unchanged, so behaviour there is identical
    to before.
    """
    env = os.environ.copy()
    limit = getattr(settings, "NUCLEI_GOMEMLIMIT", "")
    if limit:
        env["GOMEMLIMIT"] = limit
        env.setdefault("GOGC", "50")
    return env
