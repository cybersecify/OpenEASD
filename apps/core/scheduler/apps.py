from django.apps import AppConfig


class SchedulerConfig(AppConfig):
    """Scheduling on this branch is DBOS @scheduled workflows
    (apps/core/durable/workflows.py), registered when the `dbos_worker`
    management command imports that module. There is nothing to set up in
    ready() — the old Django-Q qcluster-guarded schedule registration is gone.
    """

    name = "apps.core.scheduler"
    label = "scheduler"
