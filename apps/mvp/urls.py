from django.urls import path

from . import views

app_name = "mvp"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("activity/", views.dashboard_activity, name="activity"),
]
