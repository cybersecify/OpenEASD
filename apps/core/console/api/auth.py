"""Project JWT auth that also enforces the forced-password-change gate.

Every API router authenticates with this ``JWTAuth`` instead of importing
ninja_jwt's directly. Beyond normal token validation, it blocks a user whose
``UserProfile.must_change_password`` flag is set from doing anything except
reading their own user record and setting a new password — so the forced
password change is enforced server-side, not only by the React redirect. A
holder of default ``admin/admin`` credentials therefore cannot use the API by
talking to it directly.
"""

from ninja.errors import HttpError
from ninja_jwt.authentication import JWTAuth as _BaseJWTAuth

# Path suffixes a flagged user may still reach: read own identity (to see the
# flag) and change the password. The token issue/refresh/blacklist endpoints do
# not use this auth class at all, so they need no exemption here.
_EXEMPT_SUFFIXES = ("/user/", "/user/change-password/")


def _is_exempt(request) -> bool:
    path = request.path.rstrip("/") + "/"
    return path.endswith(_EXEMPT_SUFFIXES)


class JWTAuth(_BaseJWTAuth):
    def authenticate(self, request, token):
        user = super().authenticate(request, token)
        if user is None:
            return None
        profile = getattr(user, "profile", None)
        if profile is not None and profile.must_change_password and not _is_exempt(request):
            raise HttpError(403, "Password change required before continuing")
        return user
