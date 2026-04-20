# Django Ninja Migration Design

**Date:** 2026-04-20
**Project:** OpenEASD
**Scope:** Replace plain `JsonResponse` REST API with Django Ninja + JWT auth

---

## Goal

Migrate `apps/core/api/` from hand-rolled `JsonResponse` views to Django Ninja,
matching the architecture pattern used in the chess engine backend. Frontend
changes (switching from session to JWT) are deferred — backend only.

---

## Key Decisions

| Decision | Choice | Reason |
|---|---|---|
| Auth | JWT (access + refresh tokens) | Matches chess engine, more portable |
| User model | Built-in Django User (no change) | No mid-project model swap risk |
| Token invalidation | JTI blacklist on logout only | Simpler than token versioning; password-change invalidation deferred |
| Response format | Flat (chess engine style) | Idiomatic Ninja; cleaner than `{"ok", "data", "errors"}` envelope |
| Router placement | Distributed — each app owns `api.py` | Matches chess engine; better separation of concerns |
| Pagination | Inline in response dict | `{"results": [...], "total": N, "page": N, "per_page": N}` |
| Swagger docs | Auto-enabled at `/api/docs` | Free with Ninja |

---

## Folder Structure

### New files

```
apps/
├── core/
│   └── api/
│       ├── __init__.py
│       ├── ninja.py          ← NinjaAPI instance, exception handlers, router registration
│       ├── auth.py           ← JWT helpers (create/decode token) + AuthBearer + auth_bearer singleton
│       ├── tokens/
│       │   ├── __init__.py
│       │   └── models.py     ← BlacklistedToken(jti, expires_at)
│       └── urls.py           ← updated: points to ninja_api.urls
│
├── dashboard/
│   └── api.py                ← /api/dashboard/
├── domains/
│   └── api.py                ← /api/domains/
├── scans/
│   └── api.py                ← /api/scans/ + /api/scans/findings/ + /api/scheduled/
├── workflows/
│   └── api.py                ← /api/workflows/ + /api/workflows/tools/
└── insights/
    └── api.py                ← /api/insights/
```

### Deleted files

```
apps/core/api/decorators.py         ← replaced by AuthBearer
apps/core/api/serializers.py        ← replaced by per-router Pydantic schemas
apps/core/api/views/auth.py         ← moved into apps/core/api/ninja.py auth router
apps/core/api/views/dashboard.py    ← moved to apps/dashboard/api.py
apps/core/api/views/domains.py      ← moved to apps/domains/api.py
apps/core/api/views/scans.py        ← moved to apps/scans/api.py
apps/core/api/views/workflows.py    ← moved to apps/workflows/api.py
apps/core/api/views/insights.py     ← moved to apps/insights/api.py
```

### Tool apps — no api.py needed

`domain_security`, `subfinder`, `dnsx`, `naabu`, `httpx`, `nuclei`, `nmap`,
`tls_checker`, `ssh_checker`, `web_checker`, `service_detection` are pure
execution engines. Their data is exposed via the scans router.

---

## JWT Auth

### `apps/core/api/auth.py`

```python
from ninja.security import HttpBearer
import jwt, uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from .tokens.models import BlacklistedToken

def create_access_token(user_id: int) -> str:
    payload = {
        'user_id': user_id, 'type': 'access',
        'exp': datetime.now(dt_timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def create_refresh_token(user_id: int) -> str:
    payload = {
        'user_id': user_id, 'type': 'refresh',
        'jti': str(uuid.uuid4()),
        'exp': datetime.now(dt_timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def decode_token(token: str, expected_type: str) -> int | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        if payload.get('type') != expected_type:
            return None
        if expected_type == 'refresh':
            jti = payload.get('jti')
            if jti and BlacklistedToken.objects.filter(jti=jti).exists():
                return None
        return payload.get('user_id')
    except jwt.PyJWTError:
        return None

class AuthBearer(HttpBearer):
    def authenticate(self, request, token: str):
        user_id = decode_token(token, 'access')
        if not user_id:
            return None
        User = get_user_model()
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

auth_bearer = AuthBearer()
```

### `apps/core/api/tokens/models.py`

```python
from django.db import models

class BlacklistedToken(models.Model):
    jti = models.CharField(max_length=36, unique=True)
    expires_at = models.DateTimeField()

    class Meta:
        indexes = [models.Index(fields=['jti'])]
```

### Settings additions

```python
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
```

---

## Auth Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/login/` | None | Returns `{"access": "...", "refresh": "..."}` |
| `POST` | `/api/auth/logout/` | Bearer | Blacklists refresh token JTI |
| `POST` | `/api/auth/refresh/` | None | Exchanges refresh for new access token |
| `GET` | `/api/auth/user/` | Bearer | Returns current user info |

---

## Response Format

### Success

Data returned directly — no envelope:

```json
{"domains": [...], "total": 42}
{"id": 1, "name": "example.com", "is_active": true}
{"results": [...], "total": 100, "page": 1, "per_page": 20}
```

### Error

```json
{"error": {"code": "NOT_FOUND", "message": "Domain not found"}}
{"error": {"code": "VALIDATION_ERROR", "message": "Validation failed", "details": [...]}}
```

### Status code mapping

| HTTP | Code string |
|---|---|
| 400 | `BAD_REQUEST` |
| 401 | `UNAUTHORIZED` |
| 403 | `FORBIDDEN` |
| 404 | `NOT_FOUND` |
| 409 | `CONFLICT` |
| 422 | `VALIDATION_ERROR` |
| 500 | `INTERNAL_ERROR` |

---

## `apps/core/api/ninja.py`

```python
from ninja import NinjaAPI
from ninja.errors import HttpError, ValidationError
from django.http import JsonResponse

from .auth import auth_router
from apps.dashboard.api import router as dashboard_router
from apps.domains.api import router as domains_router
from apps.scans.api import router as scans_router
from apps.workflows.api import router as workflows_router
from apps.insights.api import router as insights_router

api = NinjaAPI(title='OpenEASD API', version='1.0', docs_url='/api/docs')

api.add_router('/auth',      auth_router)
api.add_router('/dashboard', dashboard_router)
api.add_router('/domains',   domains_router)
api.add_router('/scans',     scans_router)
api.add_router('/workflows', workflows_router)
api.add_router('/insights',  insights_router)

_STATUS_CODES = {
    400: 'BAD_REQUEST', 401: 'UNAUTHORIZED', 403: 'FORBIDDEN',
    404: 'NOT_FOUND',   409: 'CONFLICT',     422: 'VALIDATION_ERROR',
    500: 'INTERNAL_ERROR',
}

@api.exception_handler(HttpError)
def http_error_handler(request, exc):
    code = _STATUS_CODES.get(exc.status_code, 'ERROR')
    return JsonResponse({'error': {'code': code, 'message': str(exc.message)}}, status=exc.status_code)

@api.exception_handler(ValidationError)
def validation_error_handler(request, exc):
    return JsonResponse(
        {'error': {'code': 'VALIDATION_ERROR', 'message': 'Validation failed', 'details': exc.errors}},
        status=422,
    )
```

---

## Per-Router Schema Pattern

Schemas defined inline in each `api.py`. No shared `serializers.py`.

```python
# apps/domains/api.py
from ninja import Router, Schema
from ninja.errors import HttpError
from apps.core.api.auth import auth_bearer

router = Router(auth=auth_bearer)

class DomainIn(Schema):
    name: str

class DomainOut(Schema):
    id: int
    name: str
    is_active: bool

@router.get('/', response=list[DomainOut])
def list_domains(request):
    ...

@router.post('/', response={201: DomainOut})
def create_domain(request, data: DomainIn):
    ...
```

---

## Migration Steps

Execute in order, one commit per router:

1. `uv add django-ninja pyjwt` — install deps
2. Create `apps/core/api/tokens/models.py` + migration
3. Write `apps/core/api/auth.py` — JWT helpers + AuthBearer
4. Write `apps/core/api/ninja.py` — NinjaAPI + exception handlers (no routers yet)
5. Convert `apps/dashboard/api.py`
6. Convert `apps/domains/api.py`
7. Convert `apps/scans/api.py`
8. Convert `apps/workflows/api.py`
9. Convert `apps/insights/api.py`
10. Add auth router to `ninja.py`
11. Update `apps/core/api/urls.py` → switch to `api.urls`
12. Delete `apps/core/api/views/`, `decorators.py`, `serializers.py`
13. Update tests — replace session login with `Authorization: Bearer <token>`
14. Run `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`

---

## API Endpoint Mapping (old → new)

| Old path | New path | Router |
|---|---|---|
| `GET /api/auth/user/` | `GET /api/auth/user/` | ninja.py auth |
| `POST /api/auth/login/` | `POST /api/auth/login/` | ninja.py auth |
| `POST /api/auth/logout/` | `POST /api/auth/logout/` | ninja.py auth |
| *(new)* | `POST /api/auth/refresh/` | ninja.py auth |
| `GET /api/dashboard/` | `GET /api/dashboard/` | dashboard |
| `GET /api/domains/` | `GET /api/domains/` | domains |
| `POST /api/domains/` | `POST /api/domains/` | domains |
| `POST /api/domains/<pk>/toggle/` | `POST /api/domains/<pk>/toggle/` | domains |
| `POST /api/domains/<pk>/delete/` | `POST /api/domains/<pk>/delete/` | domains |
| `GET /api/scans/` | `GET /api/scans/` | scans |
| `POST /api/scans/start/` | `POST /api/scans/start/` | scans |
| `GET /api/scans/<uuid>/` | `GET /api/scans/<uuid>/` | scans |
| `GET /api/scans/<uuid>/status/` | `GET /api/scans/<uuid>/status/` | scans |
| `POST /api/scans/<uuid>/stop/` | `POST /api/scans/<uuid>/stop/` | scans |
| `POST /api/scans/<uuid>/delete/` | `POST /api/scans/<uuid>/delete/` | scans |
| `GET /api/scans/findings/` | `GET /api/scans/findings/` | scans |
| `POST /api/scans/findings/<id>/status/` | `POST /api/scans/findings/<id>/status/` | scans |
| `GET /api/scheduled/` | `GET /api/scheduled/` | scans |
| `POST /api/scheduled/<job_id>/cancel/` | `POST /api/scheduled/<job_id>/cancel/` | scans |
| `GET /api/workflows/` | `GET /api/workflows/` | workflows |
| `POST /api/workflows/create/` | `POST /api/workflows/create/` | workflows |
| `GET /api/workflows/tools/` | `GET /api/workflows/tools/` | workflows |
| `GET /api/workflows/<pk>/` | `GET /api/workflows/<pk>/` | workflows |
| `POST /api/workflows/<pk>/update/` | `POST /api/workflows/<pk>/update/` | workflows |
| `POST /api/workflows/<pk>/delete/` | `POST /api/workflows/<pk>/delete/` | workflows |
| `POST /api/workflows/<pk>/steps/<tool>/toggle/` | `POST /api/workflows/<pk>/steps/<tool>/toggle/` | workflows |
| `GET /api/insights/` | `GET /api/insights/` | insights |

All paths preserved — no frontend URL changes needed.

---

## Out of Scope

- Frontend JWT integration (deferred)
- Custom User model / token versioning
- CORS configuration changes
- Legacy HTMX/Django-template routes (unchanged)
