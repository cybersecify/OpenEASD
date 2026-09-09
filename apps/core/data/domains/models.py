from django.db import models


class Domain(models.Model):
    name = models.CharField(max_length=255, unique=True, db_index=True)
    is_primary = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    added_at = models.DateTimeField(auto_now_add=True)
    monitoring_interval_hours = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class DomainAuthorization(models.Model):
    AUTH_TYPES = [
        ("owner", "Domain Owner"),
        ("written_consent", "Written Consent"),
        ("bug_bounty", "Bug Bounty Program"),
    ]

    domain = models.OneToOneField(
        Domain,
        on_delete=models.CASCADE,
        related_name="authorization",
    )
    auth_type = models.CharField(max_length=32, choices=AUTH_TYPES)
    authorized_at = models.DateField()
    authorized_by = models.CharField(max_length=255)
    auth_reference = models.CharField(max_length=500, blank=True)

    def __str__(self):
        return f"{self.domain.name} — {self.get_auth_type_display()}"
