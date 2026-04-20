from django.urls import path
from apps.core.api.views.auth import api_user_view, api_login_view, api_logout_view
from apps.core.api.views.dashboard import api_dashboard
from apps.core.api.views.domains import api_domain_list, api_domain_toggle, api_domain_delete
from apps.core.api.views.scans import (
    api_scan_list, api_scan_start, api_scan_detail, api_scan_status,
    api_scan_stop, api_scan_delete, api_vulnerability_list,
    api_finding_update_status, api_scheduled_list, api_scheduled_cancel,
    api_url_list,
)
from apps.core.api.views.workflows import (
    api_workflow_list, api_workflow_create, api_workflow_detail,
    api_workflow_update, api_workflow_delete, api_workflow_toggle_step,
    api_workflow_tools
)
from apps.core.api.views.insights import api_insights

urlpatterns = [
    # Auth
    path("auth/user/", api_user_view, name="api-user"),
    path("auth/login/", api_login_view, name="api-login"),
    path("auth/logout/", api_logout_view, name="api-logout"),
    # Dashboard
    path("dashboard/", api_dashboard, name="api-dashboard"),
    # Domains
    path("domains/", api_domain_list, name="api-domain-list"),
    path("domains/<int:pk>/toggle/", api_domain_toggle, name="api-domain-toggle"),
    path("domains/<int:pk>/delete/", api_domain_delete, name="api-domain-delete"),
    # Scans — static paths before variable paths
    path("scans/", api_scan_list, name="api-scan-list"),
    path("scans/start/", api_scan_start, name="api-scan-start"),
    path("scans/findings/", api_vulnerability_list, name="api-vulnerability-list"),
    path("scans/urls/", api_url_list, name="api-url-list"),
    path("scans/findings/<int:finding_id>/status/", api_finding_update_status, name="api-finding-update-status"),
    path("scans/<uuid:session_uuid>/", api_scan_detail, name="api-scan-detail"),
    path("scans/<uuid:session_uuid>/status/", api_scan_status, name="api-scan-status"),
    path("scans/<uuid:session_uuid>/stop/", api_scan_stop, name="api-scan-stop"),
    path("scans/<uuid:session_uuid>/delete/", api_scan_delete, name="api-scan-delete"),
    # Scheduled
    path("scheduled/", api_scheduled_list, name="api-scheduled-list"),
    path("scheduled/<str:job_id>/cancel/", api_scheduled_cancel, name="api-scheduled-cancel"),
    # Workflows
    path("workflows/", api_workflow_list, name="api-workflow-list"),
    path("workflows/create/", api_workflow_create, name="api-workflow-create"),
    path("workflows/tools/", api_workflow_tools, name="api-workflow-tools"),
    path("workflows/<int:pk>/", api_workflow_detail, name="api-workflow-detail"),
    path("workflows/<int:pk>/update/", api_workflow_update, name="api-workflow-update"),
    path("workflows/<int:pk>/delete/", api_workflow_delete, name="api-workflow-delete"),
    path("workflows/<int:pk>/steps/<str:tool>/toggle/", api_workflow_toggle_step, name="api-workflow-toggle-step"),
    # Insights
    path("insights/", api_insights, name="api-insights"),
]
