from django.urls import path
from . import views

urlpatterns = [
    path("", views.domain_list, name="domain-list"),
    path("<int:pk>/toggle/", views.domain_toggle, name="domain-toggle"),
    path("<int:pk>/delete/", views.domain_delete, name="domain-delete"),
]
