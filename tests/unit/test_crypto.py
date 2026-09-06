"""Tests for at-rest secret encryption (apps.core.crypto + EncryptedField)."""

import pytest
from cryptography.fernet import Fernet, InvalidToken
from django.db import connection

from apps.core import crypto


class TestCryptoHelpers:
    def test_roundtrip(self):
        assert crypto.decrypt(crypto.encrypt("s3cr3t-value")) == "s3cr3t-value"

    def test_ciphertext_differs_from_plaintext(self):
        assert crypto.encrypt("hello") != "hello"

    def test_encryption_is_nondeterministic(self):
        # Fernet uses a random IV — same input, different ciphertext.
        assert crypto.encrypt("x") != crypto.encrypt("x")

    def test_try_decrypt_tolerates_legacy_plaintext(self):
        assert crypto.try_decrypt("not-a-fernet-token") == "not-a-fernet-token"

    def test_try_decrypt_empty_returns_empty(self):
        assert crypto.try_decrypt("") == ""

    def test_try_decrypt_real_token(self):
        assert crypto.try_decrypt(crypto.encrypt("k")) == "k"

    def test_unicode_roundtrip(self):
        assert crypto.decrypt(crypto.encrypt("pä$$wörd-🔑")) == "pä$$wörd-🔑"


class TestKeyResolution:
    def test_secret_key_derivation_deterministic(self, settings):
        settings.FIELD_ENCRYPTION_KEY = ""
        settings.SECRET_KEY = "a-stable-secret-key-for-this-test"
        token = crypto.encrypt("value")
        assert crypto.decrypt(token) == "value"

    def test_explicit_field_key_overrides_secret_key(self, settings):
        settings.FIELD_ENCRYPTION_KEY = Fernet.generate_key().decode()
        assert crypto.decrypt(crypto.encrypt("value")) == "value"

    def test_wrong_key_cannot_decrypt(self, settings):
        settings.FIELD_ENCRYPTION_KEY = Fernet.generate_key().decode()
        token = crypto.encrypt("value")
        settings.FIELD_ENCRYPTION_KEY = Fernet.generate_key().decode()  # rotate
        with pytest.raises(InvalidToken):
            crypto.decrypt(token)


@pytest.mark.django_db
class TestEncryptedFieldStorage:
    def _raw(self, model, field, pk):
        with connection.cursor() as cur:
            cur.execute(
                f"SELECT {field} FROM {model._meta.db_table} WHERE id = %s", [pk]
            )
            return cur.fetchone()[0]

    def test_db_holds_ciphertext_orm_returns_plaintext(self):
        from apps.core.ai.models import AISettings
        cfg = AISettings.get()
        cfg.cloudflare_api_token = "super-secret-token"
        cfg.save()

        raw = self._raw(AISettings, "cloudflare_api_token", cfg.id)
        assert raw != "super-secret-token"
        assert "super-secret-token" not in raw  # not recoverable from the column

        cfg.refresh_from_db()
        assert cfg.cloudflare_api_token == "super-secret-token"  # transparent read

    def test_blank_secret_stays_blank_unencrypted(self):
        from apps.core.ai.models import AISettings
        cfg = AISettings.get()
        cfg.cloudflare_api_token = ""
        cfg.save()
        assert self._raw(AISettings, "cloudflare_api_token", cfg.id) == ""

    def test_legacy_plaintext_row_is_readable(self):
        # Rows written before encryption existed must still read back.
        from apps.core.ai.models import AISettings
        cfg = AISettings.get()
        cfg.save()
        with connection.cursor() as cur:
            cur.execute(
                f"UPDATE {AISettings._meta.db_table} "
                f"SET cloudflare_api_token = %s WHERE id = %s",
                ["legacy-plaintext-key", cfg.id],
            )
        cfg.refresh_from_db()
        assert cfg.cloudflare_api_token == "legacy-plaintext-key"

    def test_webhook_urls_encrypted(self):
        from apps.core.notifications.models import NotificationConfig
        cfg, _ = NotificationConfig.objects.get_or_create(pk=1)
        cfg.slack_webhook_url = "https://hooks.slack.com/services/T/B/secret"
        cfg.save()
        raw = self._raw(NotificationConfig, "slack_webhook_url", cfg.id)
        assert "secret" not in raw
        cfg.refresh_from_db()
        assert cfg.slack_webhook_url == "https://hooks.slack.com/services/T/B/secret"

    def test_amass_build_config_receives_plaintext(self):
        from apps.amass.models import AmassConfig
        cfg = AmassConfig.get()
        cfg.shodan_key = "sk-plain-123"
        cfg.save()
        cfg.refresh_from_db()
        sources = cfg.build_datasource_config()
        assert any(s["creds"].get("apikey") == "sk-plain-123" for s in sources)

    def test_subfinder_build_config_receives_plaintext(self):
        from apps.subfinder.models import SubfinderConfig
        cfg = SubfinderConfig.get()
        cfg.hunter_key = "hk-plain-456"
        cfg.save()
        cfg.refresh_from_db()
        assert cfg.build_provider_config().get("hunter") == ["hk-plain-456"]
