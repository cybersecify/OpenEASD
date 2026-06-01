"""User management API — superuser only."""

from django.contrib.auth import get_user_model
from ninja import Router
from ninja.errors import HttpError
from ninja_jwt.authentication import JWTAuth

User = get_user_model()


class SuperuserAuth(JWTAuth):
    def authenticate(self, request, token):
        user = super().authenticate(request, token)
        if user is None or not user.is_superuser:
            raise HttpError(403, "Superuser access required")
        return user


router = Router(auth=SuperuserAuth())


def _serialize(u) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "is_superuser": u.is_superuser,
        "is_active": u.is_active,
        "date_joined": u.date_joined.isoformat(),
        "last_login": u.last_login.isoformat() if u.last_login else None,
    }


@router.get("/", response=list)
def list_users(request):
    return [_serialize(u) for u in User.objects.order_by("date_joined")]
