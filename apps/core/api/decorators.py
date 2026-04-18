from functools import wraps
from django.http import JsonResponse


def api_login_required(view_fn):
    @wraps(view_fn)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"ok": False, "data": None, "errors": "Unauthorized"}, status=401)
        return view_fn(request, *args, **kwargs)
    return wrapper
