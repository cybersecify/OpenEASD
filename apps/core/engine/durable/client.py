"""Enqueue-only DBOS client + system-database URL — a **leaf** module.

Deliberately kept separate from `dbos_app` (which imports `workflows` to register
the workflow/step decorators): `task.py` and `workflows.py` enqueue via
`get_client()`, and if they imported it from `dbos_app` the chain
`workflows → task → dbos_app → workflows` would form an import cycle. This module
imports nothing from the package except leaf `constants`, so it closes no cycle.
"""

from django.conf import settings

from .constants import SYSTEM_SCHEMA as _SYSTEM_SCHEMA

_client = None


def system_database_url() -> str:
    """SQLAlchemy URL for DBOS, derived from Django's default DATABASES entry
    (psycopg3 driver), unless DBOS_DATABASE_URL overrides it."""
    override = getattr(settings, "DBOS_DATABASE_URL", "")
    if override:
        return override
    db = settings.DATABASES["default"]
    return "postgresql+psycopg://{user}:{password}@{host}:{port}/{name}".format(
        user=db["USER"],
        password=db["PASSWORD"],
        host=db["HOST"],
        port=db["PORT"] or "5432",
        name=db["NAME"],
    )


def get_client():
    """Process-wide DBOSClient for enqueue-only callers (web/gunicorn, and the
    `.delay()` path of `@durable_task`)."""
    global _client
    if _client is None:
        from dbos import DBOSClient

        _client = DBOSClient(
            system_database_url=system_database_url(),
            dbos_system_schema=_SYSTEM_SCHEMA,
            application_name=getattr(settings, "DBOS_APP_NAME", "openeasd"),
        )
    return _client
