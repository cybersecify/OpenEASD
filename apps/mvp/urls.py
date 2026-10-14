from django.urls import path

from . import views

app_name = "mvp"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("activity/", views.dashboard_activity, name="activity"),
    path("domains/", views.domains, name="domains"),
    path("domains/add/", views.domain_create, name="domain-create"),
    path("domains/<str:name>/", views.domain_detail, name="domain-detail"),
    path("domains/<str:name>/authorize/", views.domain_authorize, name="domain-authorize"),
    path("domains/<str:name>/monitoring/", views.domain_monitoring, name="domain-monitoring"),
    path("domains/<str:name>/delete/", views.domain_delete, name="domain-delete"),
]
