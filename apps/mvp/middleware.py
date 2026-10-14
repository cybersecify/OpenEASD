import logging

from django.shortcuts import redirect
from django.urls import reverse

logger = logging.getLogger(__name__)

_EXEMPT_PREFIXES = ("/static/", "/admin/", "/api/", "/reports/", "/metrics/", "/login/", "/logout/")


def must_change_password(user):
    """Defensive flag lookup: missing profile / any error -> False."""
    try:
        return bool(user.profile.must_change_password)
    except Exception:
        return False


class MustChangePasswordMiddleware:
    """Force flagged users through the change-password page (everywhere except exempt paths)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            path = request.path
            user = getattr(request, "user", None)
            if (
                not path.startswith(_EXEMPT_PREFIXES)
                and user is not None
                and user.is_authenticated
                and must_change_password(user)
                and path != reverse("mvp:change-password")
            ):
                return redirect("mvp:change-password")
        except Exception:
            logger.exception("MustChangePasswordMiddleware failed; passing through")
        return self.get_response(request)
