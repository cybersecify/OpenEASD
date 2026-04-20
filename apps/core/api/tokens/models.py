from django.db import models


class BlacklistedToken(models.Model):
    jti = models.CharField(max_length=36, unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["jti"])]

    def __str__(self):
        return f"BlacklistedToken({self.jti})"
