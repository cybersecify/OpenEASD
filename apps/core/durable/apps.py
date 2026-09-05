from django.apps import AppConfig


class DurableConfig(AppConfig):
    """DBOS durable-execution layer (replaces Django-Q for scan execution).

    Intentionally does NO DBOS initialization in ready(): the web process
    enqueues through a lightweight DBOSClient (created lazily on first use),
    and only the `dbos_worker` management command constructs + launches the
    full DBOS engine that executes workflows. Keeping init out of ready()
    means importing this app never opens a system-database connection.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.durable"
    label = "durable"
    verbose_name = "Durable Execution"
