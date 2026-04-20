# Django Ninja Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all plain `JsonResponse` API views with Django Ninja routers + JWT auth, preserving every existing endpoint path.

**Architecture:** Centralized `apps/core/api/ninja.py` creates the `NinjaAPI` instance and mounts distributed routers from each domain app (`apps/dashboard/api.py`, `apps/domains/api.py`, `apps/scans/api.py`, `apps/workflows/api.py`, `apps/insights/api.py`). JWT auth via `HttpBearer` replaces Django session auth. A `BlacklistedToken` model enables logout invalidation via JTI blacklisting.

**Tech Stack:** `django-ninja`, `pyjwt`, Django 5, SQLite, `uv`

---

## File Map

| Action | File |
|---|---|
| Create | `apps/core/api/tokens/__init__.py` |
| Create | `apps/core/api/tokens/models.py` |
| Create | `apps/core/api/tokens/apps.py` |
| Create | `apps/core/api/auth.py` |
| Create | `apps/core/api/ninja.py` |
| Create | `apps/dashboard/api.py` |
| Create | `apps/domains/api.py` |
| Create | `apps/scans/api.py` |
| Create | `apps/workflows/api.py` |
| Create | `apps/insights/api.py` |
| Modify | `openeasd/settings.py` |
| Modify | `openeasd/urls.py` |
| Modify | `tests/conftest.py` |
| Modify | `tests/integration/test_scan_flow.py` |
| Delete | `apps/core/api/views/` (entire directory) |
| Delete | `apps/core/api/decorators.py` |
| Delete | `apps/core/api/serializers.py` |
| Delete | `apps/core/api/urls.py` |

---

## Task 1: Install Dependencies

**Files:**
- Modify: `pyproject.toml` (via uv)

- [ ] **Step 1: Add django-ninja and pyjwt**

```bash
cd /Users/rathnakara/project/OpenEASD
uv add django-ninja pyjwt
```

Expected: `pyproject.toml` and `uv.lock` updated, no errors.

- [ ] **Step 2: Verify import works**

```bash
uv run python -c "import ninja; import jwt; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore: add django-ninja and pyjwt dependencies"
```

---

## Task 2: BlacklistedToken Model

**Files:**
- Create: `apps/core/api/tokens/__init__.py`
- Create: `apps/core/api/tokens/apps.py`
- Create: `apps/core/api/tokens/models.py`
- Modify: `openeasd/settings.py`

- [ ] **Step 1: Create the tokens package**

Create `apps/core/api/tokens/__init__.py` — empty file.

Create `apps/core/api/tokens/apps.py`:
```python
from django.apps import AppConfig


class TokensConfig(AppConfig):
    name = "apps.core.api.tokens"
    label = "api_tokens"
    verbose_name = "API Tokens"
```

Create `apps/core/api/tokens/models.py`:
```python
from django.db import models


class BlacklistedToken(models.Model):
    jti = models.CharField(max_length=36, unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["jti"])]

    def __str__(self):
        return f"BlacklistedToken({self.jti})"
```

- [ ] **Step 2: Register in INSTALLED_APPS**

In `openeasd/settings.py`, add to the Local apps section (after `"apps.core.reports"`):
```python
    "apps.core.api.tokens",
```

- [ ] **Step 3: Create and run migration**

```bash
uv run manage.py makemigrations api_tokens
uv run manage.py migrate
```

Expected:
```
Migrations for 'api_tokens':
  apps/core/api/tokens/migrations/0001_initial.py
    - Create model BlacklistedToken
```

- [ ] **Step 4: Verify model works**

```bash
uv run python -c "
import django, os
os.environ['DJANGO_SETTINGS_MODULE'] = 'openeasd.settings'
django.setup()
from apps.core.api.tokens.models import BlacklistedToken
print('BlacklistedToken table OK:', BlacklistedToken.objects.count())
"
```

Expected: `BlacklistedToken table OK: 0`

- [ ] **Step 5: Commit**

```bash
git add apps/core/api/tokens/ openeasd/settings.py
git add apps/core/api/tokens/migrations/
git commit -m "feat: add BlacklistedToken model for JWT logout invalidation"
```

---

## Task 3: JWT Auth Module

**Files:**
- Create: `apps/core/api/auth.py`

- [ ] **Step 1: Add JWT settings**

In `openeasd/settings.py`, add after the `SECRET_KEY` line:
```python
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
```

- [ ] **Step 2: Write the auth module**

Create `apps/core/api/auth.py`:
```python
"""JWT authentication helpers and AuthBearer for Django Ninja."""

import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from ninja.security import HttpBearer


def create_access_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "type": "access",
        "exp": datetime.now(dt_timezone.utc)
        + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_refresh_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(dt_timezone.utc)
        + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_token(token: str, expected_type: str):
    """Decode a JWT. Returns user_id (int) on success, None on failure."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

    if payload.get("type") != expected_type:
        return None

    user_id = payload.get("user_id")
    if not user_id:
        return None

    if expected_type == "refresh":
        from apps.core.api.tokens.models import BlacklistedToken

        jti = payload.get("jti")
        if jti and BlacklistedToken.objects.filter(jti=jti).exists():
            return None

    return user_id, payload


class AuthBearer(HttpBearer):
    def authenticate(self, request, token: str):
        result = decode_token(token, "access")
        if result is None:
            return None
        user_id, _ = result
        User = get_user_model()
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None


auth_bearer = AuthBearer()
```

- [ ] **Step 3: Smoke-test the module**

```bash
uv run python -c "
import django, os
os.environ['DJANGO_SETTINGS_MODULE'] = 'openeasd.settings'
django.setup()
from apps.core.api.auth import create_access_token, decode_token
token = create_access_token(1)
result = decode_token(token, 'access')
assert result is not None
user_id, payload = result
assert user_id == 1
print('JWT auth module OK')
"
```

Expected: `JWT auth module OK`

- [ ] **Step 4: Commit**

```bash
git add apps/core/api/auth.py openeasd/settings.py
git commit -m "feat: add JWT auth module with AuthBearer and token helpers"
```

---

## Task 4: NinjaAPI Shell

**Files:**
- Create: `apps/core/api/ninja.py`

- [ ] **Step 1: Write the NinjaAPI instance with exception handlers**

Create `apps/core/api/ninja.py`:
```python
"""Central Django Ninja API instance for OpenEASD."""

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
# Auth router — login/logout/refresh/user
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
    from datetime import timezone as dt_timezone

    import jwt
    from django.conf import settings

    from apps.core.api.tokens.models import BlacklistedToken

    try:
        payload = jwt.decode(data.refresh, settings.SECRET_KEY, algorithms=["HS256"])
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp:
            import datetime

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
```

- [ ] **Step 2: Verify ninja imports without error**

```bash
uv run python -c "
import django, os
os.environ['DJANGO_SETTINGS_MODULE'] = 'openeasd.settings'
django.setup()
from apps.core.api.ninja import api
print('NinjaAPI OK, routes:', len(list(api._routers)))
"
```

Expected: `NinjaAPI OK, routes: 1` (auth router registered)

- [ ] **Step 3: Commit**

```bash
git add apps/core/api/ninja.py
git commit -m "feat: add NinjaAPI instance with exception handlers and auth router"
```

---

## Task 5: Dashboard Router

**Files:**
- Create: `apps/dashboard/api.py`
- Modify: `apps/core/api/ninja.py`

- [ ] **Step 1: Write the dashboard router**

Create `apps/dashboard/api.py`:
```python
"""Dashboard API router."""

from django.db.models import Max

from ninja import Router
from ninja.errors import HttpError

from apps.core.api.auth import auth_bearer
from apps.core.scans.models import ScanSession
from apps.core.findings.models import Finding
from apps.core.domains.models import Domain
from apps.core.insights.models import ScanSummary
from apps.core.assets.models import Subdomain, IPAddress, Port
from apps.core.web_assets.models import URL

router = Router(auth=auth_bearer)


@router.get("/")
def api_dashboard(request):
    active_domains = list(Domain.objects.filter(is_active=True))
    domain_names = [d.name for d in active_domains]

    latest_summary_ids = list(
        ScanSummary.objects.filter(domain__in=domain_names)
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    summaries = {
        s.domain: s
        for s in ScanSummary.objects.filter(id__in=latest_summary_ids)
    }

    latest_session_ids = list(
        ScanSession.objects.filter(domain__in=domain_names)
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    sessions = {
        s.domain: s
        for s in ScanSession.objects.filter(id__in=latest_session_ids)
    }

    latest_completed_ids = list(
        ScanSession.objects.filter(domain__in=domain_names, status="completed")
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )

    current_critical = 0
    current_high = 0
    domain_status = []

    for domain in active_domains:
        summary = summaries.get(domain.name)
        session = sessions.get(domain.name)
        if summary:
            current_critical += summary.critical_count
            current_high += summary.high_count
        domain_status.append({
            "id": domain.id,
            "domain": domain.name,
            "scan_status": session.status if session else "idle",
            "last_scan": session.start_time.isoformat() if session and session.start_time else None,
            "critical": summary.critical_count if summary else 0,
            "high": summary.high_count if summary else 0,
        })

    running_count = ScanSession.objects.filter(status__in=["pending", "running"]).count()

    urgent_findings = list(
        Finding.objects.filter(
            session_id__in=latest_completed_ids,
            severity__in=["critical", "high"],
        )
        .select_related("session")
        .order_by("-discovered_at")[:8]
    )

    asset_counts = {
        "subdomains": Subdomain.objects.filter(
            session_id__in=latest_completed_ids, is_active=True
        ).count(),
        "ips": IPAddress.objects.filter(session_id__in=latest_completed_ids).count(),
        "ports": Port.objects.filter(session_id__in=latest_completed_ids).count(),
        "urls": URL.objects.filter(session_id__in=latest_completed_ids).count(),
    }

    return {
        "kpi_domains": len(active_domains),
        "kpi_active_scans": running_count,
        "kpi_critical": current_critical,
        "kpi_high": current_high,
        "kpi_subdomains": asset_counts["subdomains"],
        "kpi_ips": asset_counts["ips"],
        "kpi_ports": asset_counts["ports"],
        "kpi_urls": asset_counts["urls"],
        "domain_status": domain_status,
        "urgent_findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "domain": f.session.domain,
                "source": f.source,
            }
            for f in urgent_findings
        ],
    }
```

- [ ] **Step 2: Register in ninja.py**

In `apps/core/api/ninja.py`, add after the auth router import block:
```python
from apps.dashboard.api import router as dashboard_router
api.add_router("/dashboard", dashboard_router)
```

- [ ] **Step 3: Verify route is registered**

```bash
uv run python -c "
import django, os
os.environ['DJANGO_SETTINGS_MODULE'] = 'openeasd.settings'
django.setup()
from apps.core.api.ninja import api
paths = [str(r) for r in api.urls_paths('')]
print([p for p in paths if 'dashboard' in p])
"
```

Expected: list containing `/dashboard/`

- [ ] **Step 4: Commit**

```bash
git add apps/dashboard/api.py apps/core/api/ninja.py
git commit -m "feat: add dashboard Ninja router"
```

---

## Task 6: Domains Router

**Files:**
- Create: `apps/domains/api.py`
- Modify: `apps/core/api/ninja.py`

- [ ] **Step 1: Write the domains router**

Create `apps/domains/api.py`:
```python
"""Domains API router."""

import logging

from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404

from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.api.auth import auth_bearer
from apps.core.domains.models import Domain
from apps.core.findings.models import Finding
from apps.core.insights.builder import _rebuild_finding_type_summaries
from apps.core.insights.models import ScanSummary
from apps.core.queries import latest_session_ids
from apps.core.scans.models import ScanSession

logger = logging.getLogger(__name__)

router = Router(auth=auth_bearer)


def _enrich_domains(domains):
    """Attach last_scan and findings_summary to each Domain object in-place."""
    domain_names = [d.name for d in domains]
    if not domain_names:
        return

    latest_sessions = {}
    for session in ScanSession.objects.filter(domain__in=domain_names).order_by(
        "domain", "-start_time"
    ):
        if session.domain not in latest_sessions:
            latest_sessions[session.domain] = session

    latest_ids = latest_session_ids(domains=domain_names)
    findings_by_domain = {}
    if latest_ids:
        for row in (
            Finding.objects.filter(session_id__in=latest_ids, status="open")
            .exclude(severity="info")
            .values("session__domain", "severity")
            .annotate(count=Count("id"))
        ):
            d = row["session__domain"]
            findings_by_domain.setdefault(d, {})[row["severity"]] = row["count"]

    for domain in domains:
        domain.last_scan = latest_sessions.get(domain.name)
        domain.findings_summary = findings_by_domain.get(domain.name, {})


def _serialize_domain(domain) -> dict:
    last_scan = getattr(domain, "last_scan", None)
    last_scan_data = None
    if last_scan is not None:
        last_scan_data = {
            "id": last_scan.id,
            "uuid": str(last_scan.uuid),
            "domain_name": last_scan.domain,
            "status": last_scan.status,
            "start_time": last_scan.start_time.isoformat(),
            "end_time": last_scan.end_time.isoformat() if last_scan.end_time else None,
            "total_findings": last_scan.total_findings,
        }
    return {
        "id": domain.id,
        "name": domain.name,
        "is_primary": domain.is_primary,
        "is_active": domain.is_active,
        "added_at": domain.added_at.isoformat() if domain.added_at else None,
        "last_scan": last_scan_data,
        "findings_summary": getattr(domain, "findings_summary", {}),
    }


class DomainIn(Schema):
    name: str


@router.get("/")
def list_domains(request):
    domains = list(Domain.objects.all())
    _enrich_domains(domains)
    return [_serialize_domain(d) for d in domains]


@router.post("/", response={201: dict})
def create_domain(request, data: DomainIn):
    name = data.name.strip()
    if not name:
        raise HttpError(400, "Name is required")
    if Domain.objects.filter(name=name).exists():
        raise HttpError(400, "Domain already exists")
    domain = Domain.objects.create(name=name)
    domain.last_scan = None
    domain.findings_summary = {}
    return 201, _serialize_domain(domain)


@router.post("/{pk}/toggle/")
def toggle_domain(request, pk: int):
    domain = get_object_or_404(Domain, pk=pk)
    domain.is_active = not domain.is_active
    domain.save()
    _enrich_domains([domain])
    return _serialize_domain(domain)


@router.post("/{pk}/delete/")
def delete_domain(request, pk: int):
    domain = get_object_or_404(Domain, pk=pk)
    domain_name = domain.name

    active = ScanSession.objects.filter(
        domain=domain_name, status__in=["pending", "running"]
    ).exists()
    if active:
        raise HttpError(409, "Cannot delete — a scan is currently active.")

    with transaction.atomic():
        ScanSession.objects.filter(domain=domain_name).delete()
        ScanSummary.objects.filter(domain=domain_name).delete()
        domain.delete()

    _rebuild_finding_type_summaries()
    return {"deleted": domain_name}
```

- [ ] **Step 2: Register in ninja.py**

In `apps/core/api/ninja.py`, add:
```python
from apps.domains.api import router as domains_router
api.add_router("/domains", domains_router)
```

- [ ] **Step 3: Commit**

```bash
git add apps/domains/api.py apps/core/api/ninja.py
git commit -m "feat: add domains Ninja router"
```

---

## Task 7: Scans Router

**Files:**
- Create: `apps/scans/api.py`
- Modify: `apps/core/api/ninja.py`

- [ ] **Step 1: Write the scans router**

Create `apps/scans/api.py`:
```python
"""Scans and scheduled jobs API routers."""

import datetime
import logging

from django.core.paginator import Paginator
from django.db import models
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone

from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.api.auth import auth_bearer
from apps.core.constants import SEVERITY_LEVELS
from apps.core.insights.builder import _rebuild_finding_type_summaries
from apps.core.queries import latest_session_ids
from apps.core.scans.models import ScanSession
from apps.core.scans.views import _parse_job, _schedule_once, _schedule_recurring

logger = logging.getLogger(__name__)

router = Router(auth=auth_bearer)
scheduled_router = Router(auth=auth_bearer)


# ---------------------------------------------------------------------------
# Serializer helpers
# ---------------------------------------------------------------------------

def _serialize_session_brief(session) -> dict:
    return {
        "id": session.id,
        "uuid": str(session.uuid),
        "domain_name": session.domain,
        "status": session.status,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "total_findings": session.total_findings,
    }


def _serialize_session(session) -> dict:
    return {
        "id": session.id,
        "uuid": str(session.uuid),
        "domain_name": session.domain,
        "scan_type": session.scan_type,
        "triggered_by": session.triggered_by,
        "workflow_id": session.workflow_id,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "status": session.status,
        "total_findings": session.total_findings,
    }


def _serialize_finding(finding) -> dict:
    return {
        "id": finding.id,
        "session_id": finding.session_id,
        "source": finding.source,
        "check_type": finding.check_type,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "remediation": finding.remediation,
        "target": finding.target,
        "extra": finding.extra,
        "discovered_at": finding.discovered_at.isoformat(),
        "status": finding.status,
        "assigned_to": finding.assigned_to,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "resolution_note": finding.resolution_note,
    }


def _serialize_subdomain(sub) -> dict:
    return {
        "id": sub.id,
        "domain": sub.domain,
        "subdomain": sub.subdomain,
        "source": sub.source,
        "is_active": sub.is_active,
        "resolved_at": sub.resolved_at.isoformat() if sub.resolved_at else None,
        "discovered_at": sub.discovered_at.isoformat(),
    }


def _serialize_ip(ip) -> dict:
    return {
        "id": ip.id,
        "address": ip.address,
        "version": ip.version,
        "source": ip.source,
        "discovered_at": ip.discovered_at.isoformat(),
        "subdomain_id": ip.subdomain_id,
    }


def _serialize_port(port) -> dict:
    return {
        "id": port.id,
        "address": port.address,
        "port": port.port,
        "protocol": port.protocol,
        "state": port.state,
        "service": port.service,
        "version": port.version,
        "is_web": port.is_web,
        "source": port.source,
        "discovered_at": port.discovered_at.isoformat(),
    }


def _serialize_url(url) -> dict:
    return {
        "id": url.id,
        "url": url.url,
        "scheme": url.scheme,
        "host": url.host,
        "port_number": url.port_number,
        "status_code": url.status_code,
        "title": url.title,
        "web_server": url.web_server,
        "content_length": url.content_length,
        "source": url.source,
        "discovered_at": url.discovered_at.isoformat(),
    }


def _serialize_step_result(sr) -> dict:
    return {
        "tool": sr.tool,
        "status": sr.status,
        "order": sr.order,
        "started_at": sr.started_at.isoformat() if sr.started_at else None,
        "finished_at": sr.finished_at.isoformat() if sr.finished_at else None,
        "findings_count": sr.findings_count,
        "error": sr.error or None,
    }


def _get_vuln_counts(session) -> dict:
    from apps.core.findings.models import Finding

    counts = {sev: 0 for sev in SEVERITY_LEVELS}
    for row in Finding.objects.filter(session=session).values("severity").annotate(total=Count("id")):
        if row["severity"] in counts:
            counts[row["severity"]] = row["total"]
    return counts


# ---------------------------------------------------------------------------
# Scans endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_scans(request, domain: str = "", status: str = "", page: int = 1):
    qs = ScanSession.objects.all().order_by("-start_time")
    if domain:
        qs = qs.filter(domain__icontains=domain)
    if status:
        qs = qs.filter(status=status)

    paginator = Paginator(qs, 25)
    p = paginator.get_page(page)
    return {
        "results": [_serialize_session_brief(s) for s in p],
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


class ScanStartRequest(Schema):
    domain: str
    schedule_type: str = "now"
    workflow_id: int | None = None
    scheduled_at: str | None = None
    recurrence: str = "daily"
    recurrence_time: str = "00:00"


@router.post("/start/", response={201: dict})
def start_scan(request, data: ScanStartRequest):
    domain = data.domain.strip()
    if not domain:
        raise HttpError(400, "domain is required")

    if data.schedule_type == "now":
        from apps.core.scans.pipeline import create_scan_session
        from apps.core.scans.tasks import run_scan_task

        workflow = None
        if data.workflow_id is not None:
            from apps.core.workflows.models import Workflow

            try:
                workflow = Workflow.objects.get(pk=data.workflow_id)
            except Workflow.DoesNotExist:
                raise HttpError(404, "Workflow not found")

        session = create_scan_session(domain, workflow=workflow)
        if session is None:
            raise HttpError(409, "A scan is already running for this domain.")
        run_scan_task(session.id)
        return 201, {"uuid": str(session.uuid)}

    elif data.schedule_type == "once":
        if not data.scheduled_at:
            raise HttpError(400, "scheduled_at is required for schedule_type=once")
        try:
            scheduled_at = datetime.datetime.fromisoformat(data.scheduled_at)
        except ValueError:
            raise HttpError(400, "Invalid ISO datetime format for scheduled_at")
        _schedule_once(domain, scheduled_at)
        return 201, {"scheduled_at": scheduled_at.isoformat()}

    elif data.schedule_type == "recurring":
        try:
            recurrence_time = datetime.datetime.strptime(data.recurrence_time, "%H:%M").time()
        except ValueError:
            raise HttpError(400, "recurrence_time must be HH:MM format")
        _schedule_recurring(domain, data.recurrence, recurrence_time)
        return 201, {"recurrence": data.recurrence}

    raise HttpError(400, "schedule_type must be 'now', 'once', or 'recurring'")


@router.get("/findings/")
def list_findings(
    request,
    severity: str = "",
    domain: str = "",
    status: str = "",
    source: str = "",
    session_id: int = 0,
    page: int = 1,
):
    from apps.core.findings.models import Finding

    latest_ids = latest_session_ids()
    base_qs = Finding.objects.select_related("session")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=latest_ids)

    count_open_critical = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="critical").count()
    count_open_high = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="high").count()
    count_open_medium = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="medium").count()
    count_open_low = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="low").count()

    qs = base_qs.order_by(
        models.Case(
            models.When(severity="critical", then=0),
            models.When(severity="high", then=1),
            models.When(severity="medium", then=2),
            models.When(severity="low", then=3),
            default=4,
            output_field=models.IntegerField(),
        ),
        "-discovered_at",
    )

    if severity:
        qs = qs.filter(severity=severity)
    if session_id:
        qs = qs.filter(session_id=session_id)
    if domain:
        qs = qs.filter(session__domain__icontains=domain)
    if status:
        qs = qs.filter(status=status)
    if source:
        qs = qs.filter(source=source)

    paginator = Paginator(qs, 25)
    p = paginator.get_page(page)

    return {
        "findings": [_serialize_finding(f) for f in p],
        "counts": {
            "open_critical": count_open_critical,
            "open_high": count_open_high,
            "open_medium": count_open_medium,
            "open_low": count_open_low,
        },
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


@router.get("/urls/")
def list_urls(
    request,
    domain: str = "",
    session_uuid: str = "",
    scheme: str = "",
    status_code: str = "",
    page: int = 1,
):
    from apps.core.web_assets.models import URL

    if session_uuid:
        session = get_object_or_404(ScanSession, uuid=session_uuid)
        qs = URL.objects.filter(session=session)
    else:
        latest_ids = latest_session_ids()
        qs = URL.objects.filter(session_id__in=latest_ids)
        if domain:
            qs = qs.filter(session__domain__icontains=domain)

    if scheme:
        qs = qs.filter(scheme=scheme)
    if status_code:
        try:
            qs = qs.filter(status_code=int(status_code))
        except ValueError:
            pass

    qs = qs.select_related("port", "subdomain").order_by("url")
    paginator = Paginator(qs, 50)
    p = paginator.get_page(page)

    return {
        "results": [_serialize_url(u) for u in p],
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


class FindingStatusRequest(Schema):
    status: str
    assigned_to: str | None = None
    resolution_note: str | None = None


@router.post("/findings/{finding_id}/status/")
def update_finding_status(request, finding_id: int, data: FindingStatusRequest):
    from apps.core.findings.models import Finding, STATUS_CHOICES

    finding = get_object_or_404(Finding, id=finding_id)

    valid_statuses = {s[0] for s in STATUS_CHOICES}
    if data.status not in valid_statuses:
        raise HttpError(400, f"status must be one of: {', '.join(sorted(valid_statuses))}")

    finding.status = data.status
    if data.status == "resolved" and not finding.resolved_at:
        finding.resolved_at = timezone.now()
    elif data.status != "resolved":
        finding.resolved_at = None

    if data.assigned_to is not None:
        finding.assigned_to = str(data.assigned_to)[:150]
    if data.resolution_note is not None:
        finding.resolution_note = str(data.resolution_note)[:5000]

    finding.save(update_fields=["status", "resolved_at", "assigned_to", "resolution_note"])
    return _serialize_finding(finding)


@router.get("/{session_uuid}/")
def scan_detail(request, session_uuid: str):
    from apps.core.assets.models import IPAddress, Port, Subdomain
    from apps.core.findings.models import Finding
    from apps.core.web_assets.models import URL

    session = get_object_or_404(ScanSession, uuid=session_uuid)
    vuln_counts = _get_vuln_counts(session)

    subdomains = list(Subdomain.objects.filter(session=session).order_by("-is_active", "subdomain"))
    ips = list(IPAddress.objects.filter(session=session).select_related("subdomain").order_by("address"))
    ports = list(Port.objects.filter(session=session).select_related("ip_address").order_by("address", "port"))
    urls = list(URL.objects.filter(session=session).select_related("port", "subdomain").order_by("url"))

    nmap_findings = list(
        Finding.objects.filter(session=session, source="nmap").select_related("port").order_by("-discovered_at")
    )
    domain_findings = list(
        Finding.objects.filter(session=session, source="domain_security")
        .select_related("subdomain")
        .order_by("-severity", "-discovered_at")
    )
    other_findings = list(
        Finding.objects.filter(session=session)
        .exclude(source__in=["nmap", "domain_security"])
        .select_related("port", "url")
        .order_by("-discovered_at")
    )

    return {
        "session": _serialize_session(session),
        "vuln_counts": vuln_counts,
        "subdomains": [_serialize_subdomain(s) for s in subdomains],
        "ips": [_serialize_ip(i) for i in ips],
        "ports": [_serialize_port(p) for p in ports],
        "urls": [_serialize_url(u) for u in urls],
        "nmap_findings": [_serialize_finding(f) for f in nmap_findings],
        "domain_findings": [_serialize_finding(f) for f in domain_findings],
        "other_findings": [_serialize_finding(f) for f in other_findings],
        "asset_counts": {
            "subdomains_total": len(subdomains),
            "subdomains_active": sum(1 for s in subdomains if s.is_active),
            "ips": len(ips),
            "ports": len(ports),
            "urls": len(urls),
            "nmap_findings": len(nmap_findings),
        },
    }


@router.get("/{session_uuid}/status/")
def scan_status(request, session_uuid: str):
    from apps.core.assets.models import IPAddress, Port, Subdomain
    from apps.core.findings.models import Finding
    from apps.core.web_assets.models import URL

    session = get_object_or_404(ScanSession, uuid=session_uuid)
    vuln_counts = _get_vuln_counts(session)

    sub_agg = Subdomain.objects.filter(session=session).aggregate(
        total=Count("id"),
        active=Count("id", filter=Q(is_active=True)),
    )
    asset_counts = {
        "subdomains_total": sub_agg["total"],
        "subdomains_active": sub_agg["active"],
        "ips": IPAddress.objects.filter(session=session).count(),
        "ports": Port.objects.filter(session=session).count(),
        "urls": URL.objects.filter(session=session).count(),
        "nmap_findings": Finding.objects.filter(session=session, source="nmap").count(),
    }

    step_results = []
    try:
        run = session.workflow_run
        step_results = list(run.step_results.order_by("order"))
    except Exception:
        pass

    return {
        "session": {
            "uuid": str(session.uuid),
            "status": session.status,
            "domain_name": session.domain,
        },
        "vuln_counts": vuln_counts,
        "asset_counts": asset_counts,
        "step_results": [_serialize_step_result(sr) for sr in step_results],
    }


@router.post("/{session_uuid}/stop/")
def stop_scan(request, session_uuid: str):
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    if session.status in ("pending", "running"):
        session.status = "cancelled"
        session.end_time = timezone.now()
        session.save(update_fields=["status", "end_time"])
        logger.info(f"Scan cancelled via API: session={session.id} domain={session.domain}")
    return {"status": session.status}


@router.post("/{session_uuid}/delete/")
def delete_scan(request, session_uuid: str):
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    session.delete()
    logger.info(f"Scan deleted via API: uuid={session_uuid}")
    _rebuild_finding_type_summaries()
    return {"deleted": session_uuid}


# ---------------------------------------------------------------------------
# Scheduled jobs endpoints
# ---------------------------------------------------------------------------

@scheduled_router.get("/")
def list_scheduled(request):
    from apps.core.scheduler import get_scheduler

    jobs = []
    try:
        all_jobs = get_scheduler().get_jobs()
        jobs = [p for job in all_jobs if (p := _parse_job(job)) is not None]
        jobs.sort(
            key=lambda j: (
                0 if j["job_type"] == "recurring" else 1,
                j["next_run_time"] or datetime.datetime.max.replace(tzinfo=datetime.timezone.utc),
            )
        )
    except Exception:
        logger.exception("[list_scheduled] Failed to fetch scheduled jobs")

    return [
        {
            "job_id": j["job_id"],
            "domain": j["domain"],
            "job_type": j["job_type"],
            "frequency": j["frequency"],
            "next_run_time": j["next_run_time"].isoformat() if j["next_run_time"] else None,
        }
        for j in jobs
    ]


@scheduled_router.post("/{job_id}/cancel/")
def cancel_scheduled(request, job_id: str):
    if not (job_id.startswith("once_") or job_id.startswith("recurring_")):
        raise HttpError(400, "job_id must start with 'once_' or 'recurring_'")

    from apps.core.scheduler import get_scheduler
    from apscheduler.jobstores.base import JobLookupError

    note = None
    try:
        get_scheduler().remove_job(job_id)
        logger.info(f"Scheduled job cancelled via API: {job_id}")
    except JobLookupError:
        logger.info(f"Job already gone: {job_id}")
        note = "Job already completed or was already cancelled."

    result = {"cancelled": job_id}
    if note:
        result["note"] = note
    return result
```

- [ ] **Step 2: Register both routers in ninja.py**

In `apps/core/api/ninja.py`, add:
```python
from apps.scans.api import router as scans_router, scheduled_router
api.add_router("/scans", scans_router)
api.add_router("/scheduled", scheduled_router)
```

- [ ] **Step 3: Commit**

```bash
git add apps/scans/api.py apps/core/api/ninja.py
git commit -m "feat: add scans and scheduled Ninja routers"
```

---

## Task 8: Workflows Router

**Files:**
- Create: `apps/workflows/api.py`
- Modify: `apps/core/api/ninja.py`

- [ ] **Step 1: Write the workflows router**

Create `apps/workflows/api.py`:
```python
"""Workflows API router."""

import logging

from django.shortcuts import get_object_or_404

from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.api.auth import auth_bearer
from apps.core.workflows.models import Workflow, WorkflowStep
from apps.core.workflows.registry import get_tool_choices, get_tool_phases, get_tool_requires

logger = logging.getLogger(__name__)

router = Router(auth=auth_bearer)


def _serialize_workflow(workflow) -> dict:
    steps = [
        {"tool": step.tool, "order": step.order, "enabled": step.enabled}
        for step in workflow.steps.all()
    ]
    return {
        "id": workflow.id,
        "name": workflow.name,
        "description": workflow.description,
        "is_default": workflow.is_default,
        "created_at": workflow.created_at.isoformat(),
        "updated_at": workflow.updated_at.isoformat(),
        "steps": steps,
    }


def _serialize_step_result(sr) -> dict:
    return {
        "tool": sr.tool,
        "status": sr.status,
        "order": sr.order,
        "started_at": sr.started_at.isoformat() if sr.started_at else None,
        "finished_at": sr.finished_at.isoformat() if sr.finished_at else None,
        "findings_count": sr.findings_count,
        "error": sr.error or None,
    }


@router.get("/tools/")
def list_tools(request):
    tools = [
        {"key": key, "label": label, "phase": get_tool_phases().get(key, 99)}
        for key, label in get_tool_choices()
    ]
    return {"tools": tools, "requires": get_tool_requires()}


@router.get("/")
def list_workflows(request):
    workflows = Workflow.objects.prefetch_related("steps")
    return [_serialize_workflow(w) for w in workflows]


class WorkflowIn(Schema):
    name: str
    description: str = ""
    is_default: bool = False
    tools: list[str] = []


@router.post("/create/", response={201: dict})
def create_workflow(request, data: WorkflowIn):
    name = data.name.strip()
    if not name:
        raise HttpError(400, "name is required")

    valid_tools = {key for key, _ in get_tool_choices()}
    invalid = [t for t in data.tools if t not in valid_tools]
    if invalid:
        raise HttpError(400, f"Unknown tools: {invalid}")

    tool_phases = get_tool_phases()
    workflow = Workflow.objects.create(
        name=name,
        description=data.description.strip(),
        is_default=data.is_default,
    )
    for tool in data.tools:
        WorkflowStep.objects.create(
            workflow=workflow,
            tool=tool,
            order=tool_phases.get(tool, 99),
            enabled=True,
        )
    return 201, _serialize_workflow(workflow)


@router.get("/{pk}/")
def get_workflow(request, pk: int):
    workflow = get_object_or_404(
        Workflow.objects.prefetch_related("steps", "runs__step_results"), pk=pk
    )
    tool_choices = get_tool_choices()
    tool_phases = get_tool_phases()
    enabled_tools = {s.tool: s.enabled for s in workflow.steps.all()}
    tool_steps = [
        {
            "key": key,
            "label": label,
            "enabled": enabled_tools.get(key, False),
            "phase": tool_phases.get(key, 99),
        }
        for key, label in tool_choices
    ]

    recent_runs = workflow.runs.select_related("session").order_by("-started_at")[:10]
    return {
        "workflow": _serialize_workflow(workflow),
        "tool_steps": tool_steps,
        "tool_requires": get_tool_requires(),
        "recent_runs": [
            {
                "id": run.id,
                "uuid": str(run.uuid),
                "status": run.status,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "session_uuid": str(run.session.uuid) if run.session else None,
                "step_results": [_serialize_step_result(sr) for sr in run.step_results.all()],
            }
            for run in recent_runs
        ],
    }


@router.post("/{pk}/update/")
def update_workflow(request, pk: int, data: WorkflowIn):
    workflow = get_object_or_404(Workflow, pk=pk)
    name = data.name.strip()
    if not name:
        raise HttpError(400, "name is required")

    valid_tools = {key for key, _ in get_tool_choices()}
    invalid = [t for t in data.tools if t not in valid_tools]
    if invalid:
        raise HttpError(400, f"Unknown tools: {invalid}")

    tool_phases = get_tool_phases()
    workflow.name = name
    workflow.description = data.description.strip()
    workflow.is_default = data.is_default
    workflow.save()

    workflow.steps.all().delete()
    for tool in data.tools:
        WorkflowStep.objects.create(
            workflow=workflow,
            tool=tool,
            order=tool_phases.get(tool, 99),
            enabled=True,
        )
    return _serialize_workflow(workflow)


@router.post("/{pk}/delete/")
def delete_workflow(request, pk: int):
    workflow = get_object_or_404(Workflow, pk=pk)
    name = workflow.name
    workflow.delete()
    return {"deleted": name}


@router.post("/{pk}/steps/{tool}/toggle/")
def toggle_step(request, pk: int, tool: str):
    workflow = get_object_or_404(Workflow, pk=pk)
    step, _ = WorkflowStep.objects.get_or_create(
        workflow=workflow,
        tool=tool,
        defaults={"order": get_tool_phases().get(tool, 99), "enabled": False},
    )
    step.enabled = not step.enabled
    step.save()
    return {"tool": tool, "enabled": step.enabled}
```

- [ ] **Step 2: Register in ninja.py**

In `apps/core/api/ninja.py`, add:
```python
from apps.workflows.api import router as workflows_router
api.add_router("/workflows", workflows_router)
```

- [ ] **Step 3: Commit**

```bash
git add apps/workflows/api.py apps/core/api/ninja.py
git commit -m "feat: add workflows Ninja router"
```

---

## Task 9: Insights Router

**Files:**
- Create: `apps/insights/api.py`
- Modify: `apps/core/api/ninja.py`

- [ ] **Step 1: Write the insights router**

Create `apps/insights/api.py`:
```python
"""Insights API router."""

from collections import defaultdict

from django.db.models import Count, F, Max, Q

from ninja import Router

from apps.core.api.auth import auth_bearer
from apps.core.assets.models import IPAddress, Port, Subdomain
from apps.core.domains.models import Domain
from apps.core.findings.models import Finding
from apps.core.insights.models import FindingTypeSummary, ScanSummary
from apps.core.scans.models import ScanSession
from apps.core.web_assets.models import URL

router = Router(auth=auth_bearer)


def _asset_counts_per_session(session_ids: list) -> dict:
    if not session_ids:
        return {}
    result: dict = defaultdict(dict)
    sub_rows = (
        Subdomain.objects.filter(session_id__in=session_ids)
        .values("session_id")
        .annotate(total=Count("id"), active=Count("id", filter=Q(is_active=True)))
    )
    for row in sub_rows:
        result[row["session_id"]]["subdomains"] = row["total"]
        result[row["session_id"]]["active_subdomains"] = row["active"]
    for model, key in ((IPAddress, "ips"), (Port, "ports"), (URL, "urls")):
        for row in model.objects.filter(session_id__in=session_ids).values("session_id").annotate(total=Count("id")):
            result[row["session_id"]][key] = row["total"]
    return dict(result)


@router.get("/")
def api_insights(request):
    active_domains = list(Domain.objects.filter(is_active=True).values_list("name", flat=True))

    summaries = list(
        ScanSummary.objects.filter(domain__in=active_domains)
        .select_related("session")
        .order_by("-scan_date")[:10]
    )
    summaries = list(reversed(summaries))

    kpi_open_critical = Finding.objects.filter(severity="critical", status="open").count()
    kpi_open_high = Finding.objects.filter(severity="high", status="open").count()
    kpi_new = summaries[-1].new_exposures if summaries else 0
    kpi_fixed = summaries[-1].removed_exposures if summaries else 0

    scan_trend = [
        {
            "label": f"{s.domain} ({s.scan_date.strftime('%b %d %H:%M')})",
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "tool_breakdown": s.tool_breakdown or {},
            "total": s.total_findings,
        }
        for s in summaries
    ]
    delta_trend = [
        {
            "label": f"{s.domain} ({s.scan_date.strftime('%b %d %H:%M')})",
            "new": s.new_exposures,
            "removed": s.removed_exposures,
        }
        for s in summaries
    ]

    session_ids = [s.session_id for s in summaries]
    asset_counts_by_session = _asset_counts_per_session(session_ids)
    asset_growth = [
        {
            "label": s.scan_date.strftime("%b %d %H:%M"),
            "subdomains": asset_counts_by_session.get(s.session_id, {}).get("subdomains", 0),
            "active_subdomains": asset_counts_by_session.get(s.session_id, {}).get("active_subdomains", 0),
            "ips": asset_counts_by_session.get(s.session_id, {}).get("ips", 0),
            "ports": asset_counts_by_session.get(s.session_id, {}).get("ports", 0),
            "urls": asset_counts_by_session.get(s.session_id, {}).get("urls", 0),
        }
        for s in summaries
    ]

    latest_summary_ids = list(
        ScanSummary.objects.filter(domain__in=active_domains)
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    latest_session_ids = [
        s.session_id for s in ScanSummary.objects.filter(id__in=latest_summary_ids)
    ]

    top_hosts = list(
        ScanSummary.objects.filter(id__in=latest_summary_ids)
        .annotate(count=F("total_findings"))
        .order_by("-count")
        .values("domain", "count")[:5]
    )

    top_finding_types = FindingTypeSummary.objects.order_by("-occurrence_count")[:10]

    severity_dist = (
        Finding.objects.filter(session_id__in=latest_session_ids, source="nmap")
        .values("severity")
        .annotate(count=Count("id"))
    )
    severity_distribution = {row["severity"]: row["count"] for row in severity_dist}

    nmap_findings = Finding.objects.filter(
        session_id__in=latest_session_ids, source="nmap"
    ).values("extra")
    services_agg: dict = {}
    for f in nmap_findings:
        service = (f["extra"] or {}).get("service", "") or ""
        version = (f["extra"] or {}).get("version", "") or ""
        cvss = (f["extra"] or {}).get("cvss_score") or 0
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0.0
        key = (service, version)
        agg = services_agg.setdefault(key, {"service": service, "version": version, "cve_count": 0, "max_cvss": 0.0})
        agg["cve_count"] += 1
        if cvss > agg["max_cvss"]:
            agg["max_cvss"] = cvss

    top_services = sorted(services_agg.values(), key=lambda r: r["cve_count"], reverse=True)[:5]

    chart_data = {
        "asset_growth_labels": [r["label"] for r in asset_growth],
        "asset_growth_subdomains": [r["active_subdomains"] for r in asset_growth],
        "asset_growth_ips": [r["ips"] for r in asset_growth],
        "asset_growth_ports": [r["ports"] for r in asset_growth],
        "asset_growth_urls": [r["urls"] for r in asset_growth],
        "severity_distribution": severity_distribution,
    }

    return {
        "active_domains": active_domains,
        "kpi_open_critical": kpi_open_critical,
        "kpi_open_high": kpi_open_high,
        "kpi_new": kpi_new,
        "kpi_fixed": kpi_fixed,
        "scan_trend": scan_trend,
        "delta_trend": delta_trend,
        "asset_growth": asset_growth,
        "top_hosts": top_hosts,
        "top_finding_types": [
            {
                "title": f.title,
                "check_type": f.check_type,
                "severity": f.severity,
                "occurrence_count": f.occurrence_count,
                "last_seen": f.last_seen.isoformat(),
            }
            for f in top_finding_types
        ],
        "severity_distribution": severity_distribution,
        "top_services": top_services,
        "chart_data": chart_data,
    }
```

- [ ] **Step 2: Register in ninja.py**

In `apps/core/api/ninja.py`, add:
```python
from apps.insights.api import router as insights_router
api.add_router("/insights", insights_router)
```

- [ ] **Step 3: Commit**

```bash
git add apps/insights/api.py apps/core/api/ninja.py
git commit -m "feat: add insights Ninja router"
```

---

## Task 10: Cutover — Wire URLs

**Files:**
- Modify: `openeasd/urls.py`

At this point all routers are registered in ninja.py. Switch the URL config from old urlpatterns to Ninja.

- [ ] **Step 1: Update openeasd/urls.py**

Replace the `path("api/", include("apps.core.api.urls"))` line with the Ninja API.

The file should become:
```python
"""OpenEASD URL Configuration."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.generic import TemplateView

from apps.core.api.ninja import api

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path("reports/", include("apps.core.reports.urls")),
    re_path(
        r'^(?!api/|admin|static/|media/).*$',
        ensure_csrf_cookie(TemplateView.as_view(template_name='index.html')),
        name='spa',
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

- [ ] **Step 2: Run Django system check**

```bash
uv run manage.py check
```

Expected: `System check identified no issues (0 silenced).`

- [ ] **Step 3: Verify all routes are visible**

```bash
uv run manage.py show_urls 2>/dev/null | grep "^/api" | head -30 || \
uv run python -c "
import django, os
os.environ['DJANGO_SETTINGS_MODULE'] = 'openeasd.settings'
django.setup()
from apps.core.api.ninja import api
for r in api.urls_paths(''):
    print(r)
" 2>/dev/null | head -30
```

Expected: all `/auth/`, `/dashboard/`, `/domains/`, `/scans/`, `/scheduled/`, `/workflows/`, `/insights/` paths visible.

- [ ] **Step 4: Quick smoke test — unauthenticated request returns 401**

```bash
uv run manage.py shell -c "
from django.test import Client
c = Client()
r = c.get('/api/dashboard/')
print('Status:', r.status_code)  # expect 401
import json; d = json.loads(r.content)
print('Error code:', d.get('error', {}).get('code'))  # expect UNAUTHORIZED
"
```

Expected:
```
Status: 401
Error code: UNAUTHORIZED
```

- [ ] **Step 5: Commit**

```bash
git add openeasd/urls.py
git commit -m "feat: switch API routing to Django Ninja"
```

---

## Task 11: Update Tests

**Files:**
- Modify: `tests/conftest.py`
- Modify: `tests/integration/test_scan_flow.py`

- [ ] **Step 1: Update conftest.py auth fixtures**

Replace the `auth_client` fixture to use JWT instead of session login.

In `tests/conftest.py`, change:
```python
@pytest.fixture
def auth_client(client, user):
    client.login(username="testuser", password="testpass123")
    return client
```

To:
```python
@pytest.fixture
def auth_client(client, user):
    from apps.core.api.auth import create_access_token
    token = create_access_token(user.id)
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client
```

- [ ] **Step 2: Update integration test delete assertions**

In `tests/integration/test_scan_flow.py`, find the two calls that use `auth_client.post` to `/api/domains/<pk>/delete/`. The URL is unchanged — only the auth mechanism changes, which is handled by the fixture. No URL changes needed.

Verify by grepping:
```bash
grep -n "auth_client\|/api/" tests/integration/test_scan_flow.py
```

Confirm the URLs still match `/api/domains/<pk>/delete/`.

- [ ] **Step 3: Run the fast test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v 2>&1 | tail -20
```

Expected: all tests pass. If any fail due to response shape changes (old `{"ok": true, "data": {...}}` envelope), locate those assertions and update them to read the flat response directly (e.g. `resp.json()["domain"]` instead of `resp.json()["data"]["domain"]`).

- [ ] **Step 4: Commit**

```bash
git add tests/conftest.py tests/integration/test_scan_flow.py
git commit -m "test: update auth fixtures and assertions for JWT + Ninja flat responses"
```

---

## Task 12: Delete Old Files

**Files:**
- Delete: `apps/core/api/views/` (entire directory)
- Delete: `apps/core/api/decorators.py`
- Delete: `apps/core/api/serializers.py`
- Delete: `apps/core/api/urls.py`

- [ ] **Step 1: Remove old API files**

```bash
rm -rf apps/core/api/views/
rm apps/core/api/decorators.py
rm apps/core/api/serializers.py
rm apps/core/api/urls.py
```

- [ ] **Step 2: Run system check**

```bash
uv run manage.py check
```

Expected: `System check identified no issues (0 silenced).`

- [ ] **Step 3: Run full fast test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v 2>&1 | tail -20
```

Expected: all tests pass, no import errors.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove old JsonResponse views, decorators, serializers"
```

---

## Task 13: Final Verification

- [ ] **Step 1: Run full fast test suite one more time**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all ~514 tests pass.

- [ ] **Step 2: Verify Swagger UI is accessible**

```bash
uv run manage.py runserver &
sleep 2
curl -s http://localhost:8000/api/docs/ | grep -i "openeasd" | head -3
kill %1
```

Expected: HTML response containing "OpenEASD API"

- [ ] **Step 3: Tag the release**

```bash
git tag -a v1.0 -m "v1.0: Django Ninja + JWT API migration complete"
```

---

## Endpoint Mapping Reference

All paths preserved — no frontend URL changes required until JWT frontend integration.

| Old | New | Router file |
|---|---|---|
| `POST /api/auth/login/` | `POST /api/auth/login/` | `ninja.py` auth_router |
| `POST /api/auth/logout/` | `POST /api/auth/logout/` | `ninja.py` auth_router |
| `GET /api/auth/user/` | `GET /api/auth/user/` | `ninja.py` auth_router |
| *(new)* | `POST /api/auth/refresh/` | `ninja.py` auth_router |
| `GET /api/dashboard/` | `GET /api/dashboard/` | `apps/dashboard/api.py` |
| `GET /api/domains/` | `GET /api/domains/` | `apps/domains/api.py` |
| `POST /api/domains/` | `POST /api/domains/` | `apps/domains/api.py` |
| `POST /api/domains/<pk>/toggle/` | `POST /api/domains/<pk>/toggle/` | `apps/domains/api.py` |
| `POST /api/domains/<pk>/delete/` | `POST /api/domains/<pk>/delete/` | `apps/domains/api.py` |
| `GET /api/scans/` | `GET /api/scans/` | `apps/scans/api.py` |
| `POST /api/scans/start/` | `POST /api/scans/start/` | `apps/scans/api.py` |
| `GET /api/scans/findings/` | `GET /api/scans/findings/` | `apps/scans/api.py` |
| `GET /api/scans/urls/` | `GET /api/scans/urls/` | `apps/scans/api.py` |
| `POST /api/scans/findings/<id>/status/` | `POST /api/scans/findings/<id>/status/` | `apps/scans/api.py` |
| `GET /api/scans/<uuid>/` | `GET /api/scans/<uuid>/` | `apps/scans/api.py` |
| `GET /api/scans/<uuid>/status/` | `GET /api/scans/<uuid>/status/` | `apps/scans/api.py` |
| `POST /api/scans/<uuid>/stop/` | `POST /api/scans/<uuid>/stop/` | `apps/scans/api.py` |
| `POST /api/scans/<uuid>/delete/` | `POST /api/scans/<uuid>/delete/` | `apps/scans/api.py` |
| `GET /api/scheduled/` | `GET /api/scheduled/` | `apps/scans/api.py` scheduled_router |
| `POST /api/scheduled/<job_id>/cancel/` | `POST /api/scheduled/<job_id>/cancel/` | `apps/scans/api.py` scheduled_router |
| `GET /api/workflows/` | `GET /api/workflows/` | `apps/workflows/api.py` |
| `POST /api/workflows/create/` | `POST /api/workflows/create/` | `apps/workflows/api.py` |
| `GET /api/workflows/tools/` | `GET /api/workflows/tools/` | `apps/workflows/api.py` |
| `GET /api/workflows/<pk>/` | `GET /api/workflows/<pk>/` | `apps/workflows/api.py` |
| `POST /api/workflows/<pk>/update/` | `POST /api/workflows/<pk>/update/` | `apps/workflows/api.py` |
| `POST /api/workflows/<pk>/delete/` | `POST /api/workflows/<pk>/delete/` | `apps/workflows/api.py` |
| `POST /api/workflows/<pk>/steps/<tool>/toggle/` | `POST /api/workflows/<pk>/steps/<tool>/toggle/` | `apps/workflows/api.py` |
| `GET /api/insights/` | `GET /api/insights/` | `apps/insights/api.py` |
