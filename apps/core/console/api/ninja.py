"""Central Django Ninja API instance for OpenEASD."""

from django.conf import settings
from django.http import Http404, HttpResponse, JsonResponse
from ninja import NinjaAPI, Schema
from ninja.errors import HttpError, ValidationError
from ninja_jwt.routers.obtain import obtain_pair_router   # POST /pair, POST /refresh
from ninja_jwt.routers.verify import verify_router        # POST /verify
from ninja_jwt.routers.blacklist import blacklist_router  # POST /blacklist
from ninja_jwt.exceptions import AuthenticationFailed as JWTAuthenticationFailed, TokenError

from apps.core.console.api.auth import JWTAuth

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


@api.exception_handler(Http404)
def not_found_handler(request, exc):
    # get_object_or_404 raises django Http404, which Ninja renders as
    # {"detail": "Not Found"} by default — a second 404 shape alongside
    # HttpError(404, …). Render the standard envelope so every 404 matches (F6).
    return JsonResponse(
        {"error": {"code": "NOT_FOUND", "message": "Not found"}},
        status=404,
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
# Build provenance — unauthenticated. Lets a deployer confirm exactly what
# version/commit/date the running image was built from. Baked into the image
# at build time (Dockerfile ARG/ENV + CI build-args). Defaults render cleanly
# for local runs ("dev"/"unknown").
# ---------------------------------------------------------------------------
@api.get("/version/", auth=None)
def version(request, response: HttpResponse):
    sha = settings.OPENEASD_GIT_SHA
    # no-store so a CDN never serves a stale build line after a redeploy.
    response["Cache-Control"] = "no-store"
    return {
        "version": settings.OPENEASD_VERSION,
        "git_sha": sha,
        "git_sha_short": sha[:8],
        "build_date": settings.OPENEASD_BUILD_DATE,
        # Empty on OSS default → SPA uses GitHub issue links; set on a branded
        # deployment → SPA routes "Report an issue"/"Request a feature" to mailto.
        "support_email": getattr(settings, "SUPPORT_EMAIL", ""),
    }


# Update-available check — authenticated. Compares the running build to the
# latest public GitHub release so a logged-in operator learns when their
# deployment is behind. The app never self-updates; this is a heads-up + link.
# Cached (6h) and fully fail-graceful — GitHub being down never breaks the page.
@api.get("/version/latest/", auth=JWTAuth())
def version_latest(request):
    from apps.core.console.api.update_check import check_for_update
    return check_for_update()


# ---------------------------------------------------------------------------
# Current user endpoint
# ---------------------------------------------------------------------------
class ChangePasswordIn(Schema):
    current_password: str
    new_password: str


@api.get("/user/", auth=JWTAuth())
def get_user(request):
    u = request.auth
    must_change = getattr(getattr(u, "profile", None), "must_change_password", False)
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email or "",
        "must_change_password": must_change,
    }


@api.post("/user/change-password/", auth=JWTAuth())
def change_password(request, payload: ChangePasswordIn):
    u = request.auth
    if not u.check_password(payload.current_password):
        raise HttpError(400, "Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HttpError(400, "New password must be at least 8 characters")
    # Cap length: set_password PBKDF2-hashes the raw string, so an unbounded
    # password is an authenticated CPU-burn vector.
    if len(payload.new_password) > 128:
        raise HttpError(400, "New password must be at most 128 characters")
    if payload.new_password == payload.current_password:
        raise HttpError(400, "New password must differ from current password")
    u.set_password(payload.new_password)
    u.save()
    # Clear the forced-change flag
    profile = getattr(u, "profile", None)
    if profile and profile.must_change_password:
        profile.must_change_password = False
        profile.save(update_fields=["must_change_password"])
    # Revoke existing sessions: the API is stateless JWT, so without this a
    # previously-issued (possibly stolen) refresh token keeps minting access
    # tokens after the password change. Blacklist all of the user's outstanding
    # refresh tokens so a password change actually ends other sessions. Access
    # tokens are short-lived and expire on their own.
    try:
        from ninja_jwt.token_blacklist.models import BlacklistedToken, OutstandingToken
        for ot in OutstandingToken.objects.filter(user=u):
            BlacklistedToken.objects.get_or_create(token=ot)
    except Exception:  # noqa: BLE001 — a blacklist hiccup must not fail the change
        import logging
        logging.getLogger(__name__).warning(
            "[auth] could not blacklist outstanding tokens on password change", exc_info=True
        )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Module routers (keep exactly as before)
# ---------------------------------------------------------------------------
from apps.core.console.dashboard.api import router as dashboard_router
api.add_router("/dashboard", dashboard_router)

from apps.core.data.domains.api import router as domains_router
api.add_router("/domains", domains_router)

from apps.core.engine.scans.api import router as scans_router, scheduled_router, changes_router
api.add_router("/scans", scans_router)
api.add_router("/scheduled", scheduled_router)
api.add_router("/changes", changes_router)

from apps.core.engine.workflows.api import router as workflows_router
api.add_router("/workflows", workflows_router)

from apps.core.console.insights.api import router as insights_router
api.add_router("/insights", insights_router)

from apps.core.console.notifications.api import router as notifications_router
api.add_router("/notifications", notifications_router)

from apps.core.console.credentials.api import router as credentials_router
api.add_router("/credentials", credentials_router)

from apps.core.console.ai.api import router as ai_router
api.add_router("/ai", ai_router)

from apps.core.data.findings.api import router as issues_router, findings_router
api.add_router("/issues", issues_router)
api.add_router("/findings", findings_router)

from apps.core.data.asset_inventory.api import router as assets_router
api.add_router("/assets", assets_router)
