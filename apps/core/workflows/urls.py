from django.urls import path
from . import views

urlpatterns = [
    path("", views.workflow_list, name="workflow-list"),
    path("create/", views.workflow_create, name="workflow-create"),
    path("<int:pk>/", views.workflow_detail, name="workflow-detail"),
    path("<int:pk>/delete/", views.workflow_delete, name="workflow-delete"),
    path("<int:pk>/steps/<str:tool>/toggle/", views.workflow_toggle_step, name="workflow-toggle-step"),
]
