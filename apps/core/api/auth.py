"""JWT authentication helpers and AuthBearer for Django Ninja."""

import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from ninja.security import HttpBearer


def create_access_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "type": "access",
        "exp": datetime.now(dt_timezone.utc)
        + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_refresh_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(dt_timezone.utc)
        + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_token(token: str, expected_type: str):
    """Decode a JWT. Returns (user_id, payload) on success, None on failure."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

    if payload.get("type") != expected_type:
        return None

    user_id = payload.get("user_id")
    if not user_id:
        return None

    if expected_type == "refresh":
        from apps.core.api.tokens.models import BlacklistedToken

        jti = payload.get("jti")
        if not jti:
            return None  # reject refresh tokens without jti
        if BlacklistedToken.objects.filter(jti=jti).exists():
            return None

    return user_id, payload


class AuthBearer(HttpBearer):
    def authenticate(self, request, token: str):
        result = decode_token(token, "access")
        if result is None:
            return None
        user_id, _ = result
        User = get_user_model()
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None


auth_bearer = AuthBearer()
