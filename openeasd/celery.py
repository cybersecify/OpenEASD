"""Celery application configuration for OpenEASD."""

import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openeasd.settings")

app = Celery("openeasd")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
