"""Model fields that transparently encrypt their value at rest.

Swap `models.CharField` -> `EncryptedCharField` (or `TextField` ->
`EncryptedTextField`) on any column that stores a secret (API key, token,
webhook URL). Values are Fernet-encrypted on write and decrypted on read; blank
values are stored as-is so presence checks and blank defaults keep working, and
legacy plaintext rows decrypt-tolerantly (they re-encrypt on next save).

Backed by a TEXT column regardless of the declared `max_length`, because
ciphertext is longer than the plaintext it wraps. `max_length` still bounds the
plaintext at the form/validation layer.
"""

from django.db import models

from apps.core.crypto import encrypt, try_decrypt


class EncryptedFieldMixin:
    def get_internal_type(self):
        # Ciphertext exceeds the plaintext max_length — store as TEXT.
        return "TextField"

    def from_db_value(self, value, expression, connection):
        if value is None or value == "":
            return value
        return try_decrypt(value)

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value is None or value == "":
            return value
        return encrypt(value)


class EncryptedCharField(EncryptedFieldMixin, models.CharField):
    """CharField whose value is encrypted at rest (TEXT column)."""


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    """TextField whose value is encrypted at rest."""
