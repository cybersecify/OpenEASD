from django.contrib import admin
from .models import Workflow, WorkflowStep, WorkflowRun, WorkflowStepResult


class WorkflowStepInline(admin.TabularInline):
    model = WorkflowStep
    extra = 0
    fields = ["tool", "order", "enabled"]


class WorkflowStepResultInline(admin.TabularInline):
    model = WorkflowStepResult
    extra = 0
    readonly_fields = ["tool", "order", "status", "started_at", "finished_at", "findings_count", "error"]


@admin.register(Workflow)
class WorkflowAdmin(admin.ModelAdmin):
    list_display = ["name", "is_default", "step_count", "created_at"]
    inlines = [WorkflowStepInline]

    def step_count(self, obj):
        return obj.steps.filter(enabled=True).count()
    step_count.short_description = "Enabled Steps"


@admin.register(WorkflowRun)
class WorkflowRunAdmin(admin.ModelAdmin):
    list_display = ["id", "workflow", "session", "status", "started_at", "finished_at"]
    list_filter = ["status", "workflow"]
    readonly_fields = ["started_at", "finished_at"]
    inlines = [WorkflowStepResultInline]
