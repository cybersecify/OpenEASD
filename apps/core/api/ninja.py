"""Central Django Ninja API instance for OpenEASD."""

import datetime
from django.http import JsonResponse
from ninja import NinjaAPI, Router, Schema
from ninja.errors import HttpError, ValidationError

from apps.core.api.auth import auth_bearer, create_access_token, create_refresh_token, decode_token

api = NinjaAPI(title="OpenEASD API", version="1.0", docs_url="/docs")

_STATUS_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    500: "INTERNAL_ERROR",
}


@api.exception_handler(HttpError)
def http_error_handler(request, exc):
    code = _STATUS_CODES.get(exc.status_code, "ERROR")
    return JsonResponse(
        {"error": {"code": code, "message": str(exc.message)}},
        status=exc.status_code,
    )


@api.exception_handler(ValidationError)
def validation_error_handler(request, exc):
    return JsonResponse(
        {
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Validation failed",
                "details": exc.errors,
            }
        },
        status=422,
    )


# ---------------------------------------------------------------------------
# Auth router
# ---------------------------------------------------------------------------

auth_router = Router()


class LoginRequest(Schema):
    username: str
    password: str


class LogoutRequest(Schema):
    refresh: str


class RefreshRequest(Schema):
    refresh: str


@auth_router.post("/login/")
def login(request, data: LoginRequest):
    from django.contrib.auth import authenticate

    user = authenticate(request, username=data.username, password=data.password)
    if user is None:
        raise HttpError(400, "Invalid credentials")
    return {
        "access": create_access_token(user.id),
        "refresh": create_refresh_token(user.id),
    }


@auth_router.post("/logout/", auth=auth_bearer)
def logout(request, data: LogoutRequest):
    from django.conf import settings
    import jwt as pyjwt
    from datetime import timezone as dt_timezone
    from apps.core.api.tokens.models import BlacklistedToken

    try:
        payload = pyjwt.decode(data.refresh, settings.SECRET_KEY, algorithms=["HS256"])
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp:
            expires_at = datetime.datetime.fromtimestamp(exp, tz=dt_timezone.utc)
            BlacklistedToken.objects.get_or_create(jti=jti, defaults={"expires_at": expires_at})
    except Exception:
        pass  # token already invalid — logout is idempotent
    return {"ok": True}


@auth_router.post("/refresh/")
def refresh_token(request, data: RefreshRequest):
    result = decode_token(data.refresh, "refresh")
    if result is None:
        raise HttpError(401, "Invalid or expired refresh token")
    user_id, _ = result
    return {"access": create_access_token(user_id)}


@auth_router.get("/user/", auth=auth_bearer)
def get_user(request):
    user = request.auth
    return {"id": user.id, "username": user.username, "email": user.email or ""}


api.add_router("/auth", auth_router)

from apps.core.dashboard.api import router as dashboard_router
api.add_router("/dashboard", dashboard_router)
