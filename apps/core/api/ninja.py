"""Central Django Ninja API instance for OpenEASD."""

from django.conf import settings
from django.http import JsonResponse
from ninja import NinjaAPI
from ninja.errors import HttpError, ValidationError
from ninja_jwt.routers.obtain import obtain_pair_router   # POST /pair, POST /refresh
from ninja_jwt.routers.verify import verify_router        # POST /verify
from ninja_jwt.routers.blacklist import blacklist_router  # POST /blacklist
from ninja_jwt.authentication import JWTAuth
from ninja_jwt.exceptions import AuthenticationFailed as JWTAuthenticationFailed, TokenError

api = NinjaAPI(title="OpenEASD API", version="1.0", docs_url="/docs" if settings.DEBUG else None)

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


@api.exception_handler(JWTAuthenticationFailed)
def jwt_auth_failed_handler(request, exc):
    detail = exc.detail
    if isinstance(detail, dict):
        message = str(detail.get("detail", "Authentication failed"))
    else:
        message = str(detail)
    return JsonResponse(
        {"error": {"code": "UNAUTHORIZED", "message": message}},
        status=exc.status_code,
    )


@api.exception_handler(TokenError)
def token_error_handler(request, exc):
    return JsonResponse(
        {"error": {"code": "UNAUTHORIZED", "message": str(exc)}},
        status=401,
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
# ninja-jwt token routes — /api/token/pair, /api/token/refresh, etc.
# ---------------------------------------------------------------------------
api.add_router("/token", obtain_pair_router)
api.add_router("/token", verify_router)
api.add_router("/token", blacklist_router)


# ---------------------------------------------------------------------------
# Current user endpoint
# ---------------------------------------------------------------------------
@api.get("/user/", auth=JWTAuth())
def get_user(request):
    u = request.auth
    return {"id": u.id, "username": u.username, "email": u.email or ""}


# ---------------------------------------------------------------------------
# Module routers (keep exactly as before)
# ---------------------------------------------------------------------------
from apps.core.dashboard.api import router as dashboard_router
api.add_router("/dashboard", dashboard_router)

from apps.core.domains.api import router as domains_router
api.add_router("/domains", domains_router)

from apps.core.scans.api import router as scans_router, scheduled_router
api.add_router("/scans", scans_router)
api.add_router("/scheduled", scheduled_router)

from apps.core.workflows.api import router as workflows_router
api.add_router("/workflows", workflows_router)

from apps.core.insights.api import router as insights_router
api.add_router("/insights", insights_router)
