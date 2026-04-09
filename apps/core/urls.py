"""Core app URLs."""

from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("insights/", views.insights, name="insights"),
    path("health/", views.health_check, name="health"),
]
