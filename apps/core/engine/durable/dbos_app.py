"""DBOS engine wiring for the worker.

`configure_dbos()` builds the full DBOS engine for the worker process
(`manage.py dbos_worker`), which executes and recovers workflows. Importing the
workflow module registers the `@DBOS.workflow`/`@DBOS.step`/`@durable_task`
definitions.

The enqueue-only client + system-database URL live in `client.py` (a leaf), so
`task.py`/`workflows.py` can enqueue without forming an import cycle through this
module (which imports `workflows`). Import `get_client` from `.client` directly.

The system database is the app's own Postgres, isolated in a `dbos` schema, so
there is still just one database to run (no second service).
"""

from django.conf import settings

from .client import system_database_url
from .constants import SYSTEM_SCHEMA as _SYSTEM_SCHEMA


def configure_dbos():
    """Construct (but do not launch) the DBOS engine for the worker. Importing
    the workflow module registers @DBOS.workflow/@DBOS.step/@durable_task defs."""
    from dbos import DBOS, DBOSConfig

    config: DBOSConfig = {
        "name": getattr(settings, "DBOS_APP_NAME", "openeasd"),
        "system_database_url": system_database_url(),
        "dbos_system_schema": _SYSTEM_SCHEMA,
    }
    dbos = DBOS(config=config)
    # Registers the scan queue + workflow/step/task decorators with the engine.
    from apps.core.engine.durable import workflows  # noqa: F401
    return dbos
