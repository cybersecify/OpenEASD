"""Core app URLs."""

from django.urls import path
from . import views

urlpatterns = [
    path("", views.root, name="root"),
    path("health", views.health_check, name="health"),
]
