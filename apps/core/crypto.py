"""Symmetric encryption for secrets stored at rest (BYOK API keys, webhooks).

Uses Fernet (AES-128-CBC + HMAC-SHA256) from `cryptography`, already a project
dependency. The key comes from `settings.FIELD_ENCRYPTION_KEY` when set (a
urlsafe-base64 32-byte Fernet key), otherwise it is derived deterministically
from `settings.SECRET_KEY` so existing single-key deployments get encryption
with no new required configuration.

Trade-off (documented): rotating `SECRET_KEY` without setting an explicit
`FIELD_ENCRYPTION_KEY` makes previously-encrypted secrets unreadable — the
operator must re-enter them. Rotating `SECRET_KEY` already invalidates sessions
and JWTs, so this is consistent with the existing key-rotation story. Set
`FIELD_ENCRYPTION_KEY` to decouple the two.

Fernet uses a random IV per call, so ciphertext is non-deterministic — these
fields cannot be used in equality `.filter()` lookups (the codebase only reads
them via singleton `.get()` + attribute access, so this is a non-issue).
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _fernet() -> Fernet:
    """Build a Fernet from the configured or SECRET_KEY-derived key.

    Not cached: test settings overrides (SECRET_KEY / FIELD_ENCRYPTION_KEY)
    must take effect immediately, and these fields live on rarely-read
    singleton config rows, so the cost is irrelevant.
    """
    configured = getattr(settings, "FIELD_ENCRYPTION_KEY", "") or ""
    if configured:
        key = configured.encode("ascii") if isinstance(configured, str) else configured
    else:
        digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()  # 32 bytes
        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    """Encrypt a string to a urlsafe-base64 Fernet token."""
    if plaintext is None:
        return plaintext
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    """Decrypt a Fernet token produced by `encrypt`. Raises on tampering."""
    return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")


def try_decrypt(value: str) -> str:
    """Decrypt, tolerating legacy plaintext written before encryption existed.

    A value that is not a valid Fernet token is assumed to be a pre-encryption
    plaintext secret and returned unchanged; it gets encrypted on the next save.
    """
    if not value:
        return value
    try:
        return decrypt(value)
    except (InvalidToken, ValueError):
        return value
