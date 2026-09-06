from django.contrib.auth import get_user_model
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone


class LoginThrottle(models.Model):
    """Per-IP failed-login tracking for brute-force rate limiting.

    DB-backed (not per-process cache) so the limit holds across gunicorn
    workers. Rows are created on the first failed login from an IP, reset on a
    successful login, and pruned as their window elapses. See
    `apps/core/api/ratelimit.py`.
    """
    ip = models.GenericIPAddressField(unique=True)
    failures = models.PositiveIntegerField(default=0)
    first_failure_at = models.DateTimeField(default=timezone.now)
    locked_until = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "core_login_throttle"

    def __str__(self):
        return f"LoginThrottle({self.ip}, failures={self.failures})"


class UserProfile(models.Model):
    user = models.OneToOneField(
        get_user_model(), on_delete=models.CASCADE, related_name="profile"
    )
    must_change_password = models.BooleanField(default=False)

    class Meta:
        db_table = "core_user_profile"

    def __str__(self):
        return f"Profile({self.user.username})"


@receiver(post_save, sender=get_user_model())
def _create_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)
