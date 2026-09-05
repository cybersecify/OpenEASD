"""DBOS wiring — one place that knows how to reach the system database.

Two entry points share the config:
  * `get_client()` — a lightweight DBOSClient used by the web process (and any
    caller that only needs to ENQUEUE work, never execute it).
  * `configure_dbos()` — builds the full DBOS engine for the worker process
    (`manage.py dbos_worker`), which executes and recovers workflows.

The system database is the app's own Postgres, isolated in a `dbos` schema, so
there is still just one database to run (no second service).
"""

from django.conf import settings

QUEUE_NAME = "scans"
_SYSTEM_SCHEMA = "dbos"

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


def configure_dbos():
    """Construct (but do not launch) the DBOS engine for the worker. Importing
    the workflow module registers @DBOS.workflow/@DBOS.step definitions."""
    from dbos import DBOS, DBOSConfig

    config: DBOSConfig = {
        "name": getattr(settings, "DBOS_APP_NAME", "openeasd"),
        "system_database_url": system_database_url(),
        "dbos_system_schema": _SYSTEM_SCHEMA,
    }
    dbos = DBOS(config=config)
    # Registers the scan queue + workflow/step decorators with the engine.
    from apps.core.durable import workflows  # noqa: F401
    return dbos


def get_client():
    """Process-wide DBOSClient for enqueue-only callers (web/gunicorn)."""
    global _client
    if _client is None:
        from dbos import DBOSClient

        _client = DBOSClient(
            system_database_url=system_database_url(),
            dbos_system_schema=_SYSTEM_SCHEMA,
            application_name=getattr(settings, "DBOS_APP_NAME", "openeasd"),
        )
    return _client
