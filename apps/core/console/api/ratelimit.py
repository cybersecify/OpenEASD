"""Brute-force rate limiting for the credential-login endpoint.

A DB-backed, per-IP limiter scoped to `POST /api/token/pair` (the only endpoint
that accepts a username/password). Refresh-token exchange is not limited — it
takes a token, not credentials. State lives in `LoginThrottle` so the limit is
shared across gunicorn workers (the default LocMemCache is per-process).

Tunables (settings, with defaults):
  LOGIN_RATELIMIT_ENABLED           True
  LOGIN_RATELIMIT_MAX_FAILURES      5      failures within the window -> lock
  LOGIN_RATELIMIT_WINDOW_SECONDS    900    rolling window for counting failures
  LOGIN_RATELIMIT_LOCKOUT_SECONDS   900    how long a locked IP stays locked
  LOGIN_RATELIMIT_TRUST_FORWARDED_FOR True key on X-Forwarded-For vs REMOTE_ADDR
"""

from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone

LOGIN_PATH = "/api/token/pair"


def _cfg(name, default):
    return getattr(settings, name, default)


def client_ip(request) -> str:
    """Client IP the limiter keys on.

    Behind the documented TLS reverse proxy, REMOTE_ADDR is the proxy, so the
    leftmost X-Forwarded-For entry (set by that proxy) identifies the client —
    used when LOGIN_RATELIMIT_TRUST_FORWARDED_FOR is on (the default). When it is
    off (no trusted proxy), XFF is ignored and the unspoofable REMOTE_ADDR is
    used, so an attacker cannot rotate the header to evade the limit.
    """
    if _cfg("LOGIN_RATELIMIT_TRUST_FORWARDED_FOR", True):
        xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR") or "unknown"


def seconds_locked(ip: str) -> int:
    """Seconds remaining on this IP's lockout, or 0 if it is not locked."""
    from apps.core.console.dashboard.models import LoginThrottle

    row = LoginThrottle.objects.filter(ip=ip).first()
    if row and row.locked_until:
        remaining = (row.locked_until - timezone.now()).total_seconds()
        if remaining > 0:
            return int(remaining) + 1
    return 0


def register_failure(ip: str) -> None:
    """Record a failed login; lock the IP once it crosses the threshold."""
    from apps.core.console.dashboard.models import LoginThrottle

    now = timezone.now()
    window = timedelta(seconds=_cfg("LOGIN_RATELIMIT_WINDOW_SECONDS", 900))
    max_failures = _cfg("LOGIN_RATELIMIT_MAX_FAILURES", 5)
    lockout = timedelta(seconds=_cfg("LOGIN_RATELIMIT_LOCKOUT_SECONDS", 900))

    row, created = LoginThrottle.objects.get_or_create(
        ip=ip, defaults={"first_failure_at": now}
    )
    # A fresh window if the previous one has fully elapsed (and no active lock).
    if not created and (now - row.first_failure_at) > window and (
        not row.locked_until or row.locked_until <= now
    ):
        row.failures = 0
        row.first_failure_at = now
        row.locked_until = None

    row.failures += 1
    if row.failures >= max_failures:
        row.locked_until = now + lockout
    row.save()


def register_success(ip: str) -> None:
    """A successful login clears the IP's failure record."""
    from apps.core.console.dashboard.models import LoginThrottle

    LoginThrottle.objects.filter(ip=ip).delete()


class LoginRateLimitMiddleware:
    """Locks out an IP after too many failed `POST /api/token/pair` attempts."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not (
            _cfg("LOGIN_RATELIMIT_ENABLED", True)
            and request.method == "POST"
            and request.path == LOGIN_PATH
        ):
            return self.get_response(request)

        ip = client_ip(request)
        remaining = seconds_locked(ip)
        if remaining:
            resp = JsonResponse(
                {
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": "Too many failed login attempts. Try again later.",
                    }
                },
                status=429,
            )
            resp["Retry-After"] = str(remaining)
            return resp

        response = self.get_response(request)
        if response.status_code == 200:
            register_success(ip)
        elif response.status_code == 401:  # credential mismatch
            register_failure(ip)
        return response
