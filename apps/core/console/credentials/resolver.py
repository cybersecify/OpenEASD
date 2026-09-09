"""`get_credential()` — the DB-wins-over-env credential resolver (spec C2).

Every tool should read its BYOK key through this helper instead of touching
`settings` directly, so a key set in the UI (DB) overrides the env var, and an
unset DB key falls back to the env var (and then to "").

Fail-graceful: any DB/decrypt error falls back to the env var and never raises —
a scan must never die because the credential store hiccuped.
"""

import logging

from django.conf import settings

from .models import FIELD_BY_SETTING

logger = logging.getLogger(__name__)


def get_credential(name: str) -> str:
    """Return the credential for settings key `name`: DB value if set, else the
    env/settings var, else ''. Never raises."""
    db_val = _db_value(name)
    if db_val:
        return db_val
    return getattr(settings, name, "") or ""


def credential_source(name: str) -> str:
    """Where `name` resolves from: 'db' | 'env' | 'none' (for UI feedback)."""
    if _db_value(name):
        return "db"
    if getattr(settings, name, ""):
        return "env"
    return "none"


def _db_value(name: str) -> str:
    field = FIELD_BY_SETTING.get(name)
    if not field:
        return ""
    try:
        from .models import ToolCredentials

        return getattr(ToolCredentials.get(), field, "") or ""
    except Exception:  # noqa: BLE001 — never let the credential store break a scan
        logger.warning("credentials: DB lookup for %s failed; falling back to env", name)
        return ""
