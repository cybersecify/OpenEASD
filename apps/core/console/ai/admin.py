from django.contrib import admin

from .models import (
    AgentAction,
    AgentRun,
    AIInvocation,
    AISettings,
    AISummary,
    AITriage,
    AITriageItem,
)


@admin.register(AISettings)
class AISettingsAdmin(admin.ModelAdmin):
    list_display = ("enabled", "consent_given_at", "consent_by", "consent_version")


@admin.register(AIInvocation)
class AIInvocationAdmin(admin.ModelAdmin):
    """Audit log — strictly read-only (the trail must be tamper-evident)."""

    list_display = ("created_at", "purpose", "model", "status", "total_tokens", "session_uuid")
    list_filter = ("purpose", "status")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AITriage)
class AITriageAdmin(admin.ModelAdmin):
    list_display = ("session", "status", "model", "created_at")


@admin.register(AITriageItem)
class AITriageItemAdmin(admin.ModelAdmin):
    list_display = ("triage", "rank", "priority", "finding_key")


@admin.register(AISummary)
class AISummaryAdmin(admin.ModelAdmin):
    list_display = ("session", "kind", "model", "created_at")


@admin.register(AgentRun)
class AgentRunAdmin(admin.ModelAdmin):
    list_display = ("root_session", "status", "iterations_used", "subscans_launched", "started_at")


@admin.register(AgentAction)
class AgentActionAdmin(admin.ModelAdmin):
    list_display = ("agent_run", "iteration", "action_type", "status", "created_at")
