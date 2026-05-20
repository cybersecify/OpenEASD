from django.contrib.auth import get_user_model
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


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
