from django.db import models


TOOL_CHOICES = [
    ("domain_security", "Domain Security"),
    ("subfinder", "Subfinder"),
    ("dnsx", "DNSx (Resolve)"),
    ("naabu", "Naabu (Port Scan)"),
    ("httpx", "HTTPx (Web Probe)"),
    ("nmap", "Nmap (NSE Vuln Scan)"),
    ("tls_checker", "TLS Checker"),
    # Disabled — OSS binary tools (re-enable in settings.INSTALLED_APPS to restore)
    # ("nuclei", "Nuclei (Vuln Scan)"),
]

# Execution order within a phase — enforced by runner
TOOL_PHASE = {
    "domain_security": 1,
    "subfinder": 2,
    "dnsx": 3,
    "naabu": 4,
    "httpx": 5,
    "nmap": 6,
    "tls_checker": 6,
}


class Workflow(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if self.is_default:
            Workflow.objects.exclude(pk=self.pk).update(is_default=False)
        super().save(*args, **kwargs)

    def enabled_tools(self) -> list[str]:
        """Return enabled tool names in execution order."""
        return list(
            self.steps.filter(enabled=True)
            .order_by("order")
            .values_list("tool", flat=True)
        )


class WorkflowStep(models.Model):
    workflow = models.ForeignKey(Workflow, on_delete=models.CASCADE, related_name="steps")
    tool = models.CharField(max_length=30, choices=TOOL_CHOICES)
    order = models.PositiveSmallIntegerField(default=0)
    enabled = models.BooleanField(default=True)

    class Meta:
        unique_together = [("workflow", "tool")]
        ordering = ["order"]

    def __str__(self):
        return f"{self.workflow.name} → {self.tool} ({'on' if self.enabled else 'off'})"


class WorkflowRun(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    workflow = models.ForeignKey(Workflow, on_delete=models.SET_NULL, null=True, related_name="runs")
    session = models.OneToOneField("scans.ScanSession", on_delete=models.CASCADE, related_name="workflow_run")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending", db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"Run #{self.id} [{self.status}] — {self.workflow}"


class WorkflowStepResult(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
        ("skipped", "Skipped"),
    ]

    run = models.ForeignKey(WorkflowRun, on_delete=models.CASCADE, related_name="step_results")
    tool = models.CharField(max_length=30, choices=TOOL_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    order = models.PositiveSmallIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    findings_count = models.IntegerField(default=0)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["order"]

    def __str__(self):
        return f"{self.run} / {self.tool} [{self.status}]"

    @property
    def duration_seconds(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
