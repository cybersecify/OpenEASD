"""UI-managed BYOK credentials, stored encrypted at rest.

A single row (pk=1) holding the tools' API keys. Values are Fernet-encrypted via
`EncryptedTextField` (ciphertext in the DB, plaintext via ORM attribute access).
The `get_credential()` resolver (resolver.py) reads these DB values first and
falls back to the env/settings var, so a key entered in the UI overrides the env
without a redeploy.

Bootstrap secrets (`FIELD_ENCRYPTION_KEY`, `SECRET_KEY`, `DB_*`) are deliberately
NOT here — they bootstrap the crypto + DB and cannot live in the encrypted DB.
See docs/specs/2026-09-09-credential-management.md.
"""

from django.db import models

from apps.core.fields import EncryptedTextField

# Maps a settings/env key name -> the model field that overrides it. The resolver
# and API iterate this, so adding a credential means adding one field + one entry.
FIELD_BY_SETTING = {
    "SHODAN_API_KEY": "shodan_api_key",
    "HIBP_API_KEY": "hibp_api_key",
    "GITHUB_TOKEN": "github_token",
    "GITHUB_SECRET": "github_secret",
    "DNS_HISTORY_API_URL": "dns_history_api_url",
}


class ToolCredentials(models.Model):
    """Singleton (pk=1) — the tools' BYOK API keys, encrypted at rest."""

    shodan_api_key = EncryptedTextField(blank=True, default="")
    hibp_api_key = EncryptedTextField(blank=True, default="")
    github_token = EncryptedTextField(blank=True, default="")
    github_secret = EncryptedTextField(blank=True, default="")
    dns_history_api_url = EncryptedTextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Tool credentials"

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        n = sum(1 for f in FIELD_BY_SETTING.values() if getattr(self, f, ""))
        return f"ToolCredentials ({n} key(s) set)"
