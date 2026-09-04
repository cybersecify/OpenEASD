from django.db import models

# Bump when the consent wording changes materially — a mismatch with
# AISettings.consent_version re-gates the consent dialog (D-013/D-014).
CURRENT_CONSENT_VERSION = 1


class AISettings(models.Model):
    """Singleton (pk=1) — operator-facing switches for the AI subsystem.

    Credentials are deliberately NOT here: CLOUDFLARE_ACCOUNT_ID and
    CLOUDFLARE_API_TOKEN live in the environment only (BYOK, D-014) and are
    never stored in the database or returned by the API.
    """

    enabled = models.BooleanField(default=False)
    consent_given_at = models.DateTimeField(null=True, blank=True)
    consent_by = models.CharField(max_length=150, blank=True, default="")
    consent_version = models.PositiveSmallIntegerField(default=0)

    model_override = models.CharField(max_length=100, blank=True, default="")

    triage_enabled = models.BooleanField(default=True)
    orchestration_enabled = models.BooleanField(default=True)
    summaries_enabled = models.BooleanField(default=True)

    max_agent_iterations = models.PositiveSmallIntegerField(default=3)
    max_subscans_per_scan = models.PositiveSmallIntegerField(default=2)
    max_findings_per_prompt = models.PositiveSmallIntegerField(default=50)

    class Meta:
        verbose_name = "AI settings"

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def record_consent(self, username: str):
        from django.utils import timezone

        self.consent_given_at = timezone.now()
        self.consent_by = username or ""
        self.consent_version = CURRENT_CONSENT_VERSION
        self.save(update_fields=["consent_given_at", "consent_by", "consent_version"])

    @property
    def consent_current(self) -> bool:
        return (
            self.consent_given_at is not None
            and self.consent_version == CURRENT_CONSENT_VERSION
        )

    def __str__(self):
        return f"AISettings (enabled={self.enabled})"


class AIInvocation(models.Model):
    """Per-call audit log (D-013 axis 4c, D-014 wording).

    INVARIANT: this model carries METADATA ONLY — no TextField exists on it,
    so prompt/response bodies are structurally impossible to persist here.
    session_uuid is an immutable copy so the audit trail survives session
    deletion (the FK is SET_NULL).
    """

    PURPOSE_CHOICES = [
        ("triage", "Triage"),
        ("orchestration", "Orchestration"),
        ("report_summary", "Report summary"),
        ("alert_summary", "Alert summary"),
        ("test", "Connection test"),
    ]
    STATUS_CHOICES = [
        ("ok", "OK"),
        ("timeout", "Timeout"),
        ("http_error", "HTTP error"),
        ("rate_limited", "Rate limited"),
        ("bad_json", "Bad JSON"),
        ("schema_mismatch", "Schema mismatch"),
    ]

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    session = models.ForeignKey(
        "scans.ScanSession", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="ai_invocations",
    )
    session_uuid = models.UUIDField(null=True, blank=True, db_index=True)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES)
    backend = models.CharField(max_length=40, default="cloudflare_workers_ai")
    model = models.CharField(max_length=100)
    prompt_tokens = models.IntegerField(null=True, blank=True)
    completion_tokens = models.IntegerField(null=True, blank=True)
    total_tokens = models.IntegerField(null=True, blank=True)
    finding_ids = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, db_index=True)
    duration_ms = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "AI invocation"

    def __str__(self):
        return f"{self.purpose} [{self.status}] — {self.created_at}"


class AITriage(models.Model):
    """Per-scan triage result — the analyst output the UI/report read.

    `overview` is deliberate product data (the analyst narrative), distinct
    from the audit-log no-bodies rule which covers raw prompts/responses.
    """

    STATUS_CHOICES = [
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    session = models.OneToOneField(
        "scans.ScanSession", on_delete=models.CASCADE, related_name="ai_triage"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    model = models.CharField(max_length=100, blank=True, default="")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    overview = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "AI triage"

    def __str__(self):
        return f"AITriage [{self.status}] session={self.session_id}"


class AITriageItem(models.Model):
    PRIORITY_CHOICES = [
        ("fix_now", "Fix now"),
        ("plan", "Plan"),
        ("monitor", "Monitor"),
        ("likely_noise", "Likely noise"),
    ]

    triage = models.ForeignKey(AITriage, on_delete=models.CASCADE, related_name="items")
    finding = models.ForeignKey(
        "findings.Finding", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="ai_triage_items",
    )
    # Delta-style identity copy (source:check_type:title) so the item stays
    # meaningful if the Finding row is deleted.
    finding_key = models.CharField(max_length=600, blank=True, default="")
    rank = models.PositiveIntegerField()
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES)
    rationale = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["rank"]

    def __str__(self):
        return f"#{self.rank} [{self.priority}] {self.finding_key[:60]}"


class AISummary(models.Model):
    """Plain-language summaries consumed by the PDF report and alerts."""

    KIND_CHOICES = [("report", "Report"), ("alert", "Alert")]

    session = models.ForeignKey(
        "scans.ScanSession", on_delete=models.CASCADE, related_name="ai_summaries"
    )
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    text = models.TextField(blank=True, default="")
    model = models.CharField(max_length=100, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("session", "kind")]
        verbose_name = "AI summary"

    def __str__(self):
        return f"AISummary [{self.kind}] session={self.session_id}"


class AgentRun(models.Model):
    """One orchestration run per root scan session."""

    STATUS_CHOICES = [
        ("running", "Running"),
        ("done", "Done"),
        ("failed", "Failed"),
        ("denied", "Denied"),
        ("limit_reached", "Limit reached"),
    ]

    root_session = models.OneToOneField(
        "scans.ScanSession", on_delete=models.CASCADE, related_name="agent_run"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="running")
    iterations_used = models.PositiveSmallIntegerField(default=0)
    subscans_launched = models.PositiveSmallIntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    final_summary = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "Agent run"

    def __str__(self):
        return f"AgentRun [{self.status}] session={self.root_session_id}"


class AgentAction(models.Model):
    """One row per agent decision — the user-visible orchestration record.

    `payload` carries only tool names / finding ids (never body content).
    The agent never mutates Finding.status — flag_finding is an attention
    marker recorded here, lifecycle changes stay human-only.
    """

    ACTION_CHOICES = [
        ("run_subscan", "Run subscan"),
        ("flag_finding", "Flag finding"),
        ("done", "Done"),
    ]
    STATUS_CHOICES = [
        ("executed", "Executed"),
        ("denied", "Denied"),
        ("failed", "Failed"),
        ("noop", "No-op"),
    ]

    agent_run = models.ForeignKey(AgentRun, on_delete=models.CASCADE, related_name="actions")
    iteration = models.PositiveSmallIntegerField()
    action_type = models.CharField(max_length=20, choices=ACTION_CHOICES)
    payload = models.JSONField(default=dict, blank=True)
    rationale = models.TextField(blank=True, default="")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    denial_reason = models.CharField(max_length=200, blank=True, default="")
    subscan_session = models.ForeignKey(
        "scans.ScanSession", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="triggering_agent_actions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["iteration", "id"]

    def __str__(self):
        return f"iter {self.iteration}: {self.action_type} [{self.status}]"
