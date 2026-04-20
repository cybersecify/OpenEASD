"""
Unit tests for apps/core/api/auth.py

Tests JWT token creation, decoding, edge cases, and AuthBearer authentication.
"""

import time
import uuid
from datetime import timedelta
from unittest.mock import patch

import jwt as pyjwt
import pytest
from django.contrib.auth.models import User
from django.utils import timezone

from apps.core.api.auth import (
    AuthBearer,
    auth_bearer,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from apps.core.api.tokens.models import BlacklistedToken


# ---------------------------------------------------------------------------
# create_access_token
# ---------------------------------------------------------------------------

class TestCreateAccessToken:
    def test_returns_string(self, db):
        user = User.objects.create_user("jwtuser", password="x")
        token = create_access_token(user.id)
        assert isinstance(token, str)
        assert len(token) > 20

    def test_payload_contains_expected_fields(self, db):
        from django.conf import settings
        user = User.objects.create_user("jwtuser2", password="x")
        token = create_access_token(user.id)
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        assert payload["user_id"] == user.id
        assert payload["type"] == "access"
        assert "exp" in payload

    def test_expiry_is_in_future(self, db):
        from django.conf import settings
        user = User.objects.create_user("jwtuser3", password="x")
        token = create_access_token(user.id)
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        assert payload["exp"] > time.time()

    def test_no_jti_in_access_token(self, db):
        from django.conf import settings
        user = User.objects.create_user("jwtuser4", password="x")
        token = create_access_token(user.id)
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        assert "jti" not in payload


# ---------------------------------------------------------------------------
# create_refresh_token
# ---------------------------------------------------------------------------

class TestCreateRefreshToken:
    def test_returns_string(self, db):
        user = User.objects.create_user("refuser", password="x")
        token = create_refresh_token(user.id)
        assert isinstance(token, str)

    def test_payload_has_jti(self, db):
        from django.conf import settings
        user = User.objects.create_user("refuser2", password="x")
        token = create_refresh_token(user.id)
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        assert "jti" in payload
        # Must be a valid UUID
        uuid.UUID(payload["jti"])

    def test_payload_type_is_refresh(self, db):
        from django.conf import settings
        user = User.objects.create_user("refuser3", password="x")
        token = create_refresh_token(user.id)
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        assert payload["type"] == "refresh"

    def test_each_token_has_unique_jti(self, db):
        from django.conf import settings
        user = User.objects.create_user("refuser4", password="x")
        t1 = create_refresh_token(user.id)
        t2 = create_refresh_token(user.id)
        p1 = pyjwt.decode(t1, settings.SECRET_KEY, algorithms=["HS256"])
        p2 = pyjwt.decode(t2, settings.SECRET_KEY, algorithms=["HS256"])
        assert p1["jti"] != p2["jti"]


# ---------------------------------------------------------------------------
# decode_token
# ---------------------------------------------------------------------------

class TestDecodeToken:
    def test_valid_access_token(self, db):
        user = User.objects.create_user("decuser", password="x")
        token = create_access_token(user.id)
        result = decode_token(token, "access")
        assert result is not None
        user_id, payload = result
        assert user_id == user.id
        assert payload["type"] == "access"

    def test_valid_refresh_token(self, db):
        user = User.objects.create_user("decuser2", password="x")
        token = create_refresh_token(user.id)
        result = decode_token(token, "refresh")
        assert result is not None
        user_id, payload = result
        assert user_id == user.id

    def test_wrong_type_returns_none_access_as_refresh(self, db):
        user = User.objects.create_user("decuser3", password="x")
        token = create_access_token(user.id)
        assert decode_token(token, "refresh") is None

    def test_wrong_type_returns_none_refresh_as_access(self, db):
        user = User.objects.create_user("decuser4", password="x")
        token = create_refresh_token(user.id)
        assert decode_token(token, "access") is None

    def test_invalid_token_string_returns_none(self, db):
        assert decode_token("not.a.token", "access") is None

    def test_empty_string_returns_none(self, db):
        assert decode_token("", "access") is None

    def test_expired_token_returns_none(self, db):
        from django.conf import settings
        user = User.objects.create_user("decuser5", password="x")
        # Create token that expired 1 second ago
        payload = {
            "user_id": user.id,
            "type": "access",
            "exp": timezone.now() - timedelta(seconds=1),
        }
        token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        assert decode_token(token, "access") is None

    def test_missing_user_id_returns_none(self, db):
        from django.conf import settings
        payload = {
            "type": "access",
            "exp": timezone.now() + timedelta(hours=1),
        }
        token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        assert decode_token(token, "access") is None

    def test_missing_jti_on_refresh_returns_none(self, db):
        from django.conf import settings
        user = User.objects.create_user("decuser6", password="x")
        # Refresh token without jti field
        payload = {
            "user_id": user.id,
            "type": "refresh",
            "exp": timezone.now() + timedelta(days=7),
            # no jti
        }
        token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        assert decode_token(token, "refresh") is None

    def test_blacklisted_jti_returns_none(self, db):
        user = User.objects.create_user("decuser7", password="x")
        token = create_refresh_token(user.id)
        from django.conf import settings
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        BlacklistedToken.objects.create(
            jti=payload["jti"],
            expires_at=timezone.now() + timedelta(days=7),
        )
        assert decode_token(token, "refresh") is None

    def test_wrong_secret_returns_none(self, db):
        user = User.objects.create_user("decuser8", password="x")
        payload = {
            "user_id": user.id,
            "type": "access",
            "exp": timezone.now() + timedelta(hours=1),
        }
        token = pyjwt.encode(payload, "wrong-secret", algorithm="HS256")
        assert decode_token(token, "access") is None


# ---------------------------------------------------------------------------
# AuthBearer
# ---------------------------------------------------------------------------

class TestAuthBearer:
    def test_valid_token_returns_user(self, db):
        user = User.objects.create_user("bearer1", password="x")
        token = create_access_token(user.id)

        class FakeRequest:
            pass

        result = auth_bearer.authenticate(FakeRequest(), token)
        assert result is not None
        assert result.id == user.id

    def test_invalid_token_returns_none(self, db):
        class FakeRequest:
            pass

        result = auth_bearer.authenticate(FakeRequest(), "not.valid.token")
        assert result is None

    def test_deleted_user_returns_none(self, db):
        user = User.objects.create_user("bearer2", password="x")
        token = create_access_token(user.id)
        user.delete()

        class FakeRequest:
            pass

        result = auth_bearer.authenticate(FakeRequest(), token)
        assert result is None

    def test_refresh_token_rejected_as_access(self, db):
        user = User.objects.create_user("bearer3", password="x")
        token = create_refresh_token(user.id)

        class FakeRequest:
            pass

        result = auth_bearer.authenticate(FakeRequest(), token)
        assert result is None


# ---------------------------------------------------------------------------
# BlacklistedToken model
# ---------------------------------------------------------------------------

class TestBlacklistedToken:
    def test_create_and_retrieve(self, db):
        jti = str(uuid.uuid4())
        bt = BlacklistedToken.objects.create(
            jti=jti,
            expires_at=timezone.now() + timedelta(days=7),
        )
        assert BlacklistedToken.objects.filter(jti=jti).exists()
        assert bt.jti == jti

    def test_jti_unique(self, db):
        from django.db import IntegrityError
        jti = str(uuid.uuid4())
        BlacklistedToken.objects.create(
            jti=jti, expires_at=timezone.now() + timedelta(days=7)
        )
        with pytest.raises(IntegrityError):
            BlacklistedToken.objects.create(
                jti=jti, expires_at=timezone.now() + timedelta(days=7)
            )

    def test_filter_expired(self, db):
        expired_jti = str(uuid.uuid4())
        valid_jti = str(uuid.uuid4())
        BlacklistedToken.objects.create(
            jti=expired_jti, expires_at=timezone.now() - timedelta(seconds=1)
        )
        BlacklistedToken.objects.create(
            jti=valid_jti, expires_at=timezone.now() + timedelta(days=7)
        )
        expired = BlacklistedToken.objects.filter(expires_at__lt=timezone.now())
        assert expired.filter(jti=expired_jti).exists()
        assert not expired.filter(jti=valid_jti).exists()
