import json

import django.contrib.auth as auth

from apps.core.api.decorators import api_login_required
from apps.core.api.serializers import api_response


@api_login_required
def api_user_view(request):
    if request.method != "GET":
        return api_response(errors="Method not allowed", status=405)
    user = request.user
    return api_response({"id": user.id, "username": user.username, "email": user.email})


def api_login_view(request):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return api_response(errors="Invalid JSON", status=400)

    username = body.get("username", "")
    password = body.get("password", "")

    user = auth.authenticate(request, username=username, password=password)
    if user is None:
        return api_response(data=None, errors="Invalid credentials", status=400)

    auth.login(request, user)
    return api_response({"id": user.id, "username": user.username, "email": user.email})


def api_logout_view(request):
    if request.method != "POST":
        return api_response(errors="Method not allowed", status=405)
    auth.logout(request)
    return api_response({"ok": True})
