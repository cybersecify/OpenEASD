"""Tests for the API-review robustness fixes (L1, L2, L5)."""

import datetime

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone
from ninja_jwt.tokens import AccessToken

pytestmark = pytest.mark.django_db


def _bearer(user):
    return {"HTTP_AUTHORIZATION": f"Bearer {AccessToken.for_user(user)}"}


@pytest.fixture
def user(db):
    return User.objects.create_user(username="admin", password="longpass1")


# --- L1: pagination clamp (no 500 on bad page) -------------------------------

class TestPaginationClamp:
    @pytest.mark.parametrize("path", ["/api/ai/audit/", "/api/notifications/alerts/"])
    @pytest.mark.parametrize("qs", ["?page=0", "?page=-3", "?page=1&page_size=100000"])
    def test_bad_pagination_returns_200_not_500(self, user, path, qs):
        resp = Client().get(path + qs, **_bearer(user))
        assert resp.status_code == 200  # clamped, not an unhandled negative-slice 500


# --- L2: authorize_domain rejects invalid auth_type --------------------------

class TestAuthorizeAuthType:
    def _domain(self, name="ex.com"):
        from apps.core.data.domains.models import Domain
        return Domain.objects.create(name=name)

    def _post(self, user, pk, body):
        return Client().post(
            f"/api/domains/{pk}/authorize/", data=body,
            content_type="application/json", **_bearer(user),
        )

    def test_invalid_auth_type_rejected(self, user):
        d = self._domain()
        resp = self._post(user, d.pk, '{"attestation":true,"auth_type":"bogus"}')
        assert resp.status_code == 400
        assert "auth_type" in resp.json()["error"]["message"]

    def test_valid_auth_type_accepted(self, user):
        d = self._domain("ok.com")
        resp = self._post(user, d.pk, '{"attestation":true,"auth_type":"bug_bounty"}')
        assert resp.status_code == 200

    def test_omitted_auth_type_defaults_to_owner(self, user):
        d = self._domain("def.com")
        resp = self._post(user, d.pk, '{"attestation":true}')
        assert resp.status_code == 200
        from apps.core.data.domains.models import DomainAuthorization
        assert DomainAuthorization.objects.get(domain=d).auth_type == "owner"


# --- L5: schedule_type=once rejects a past datetime --------------------------

class TestScheduleOncePast:
    def _authorized_domain(self, name="sch.com"):
        from apps.core.data.domains.models import Domain, DomainAuthorization
        d = Domain.objects.create(name=name)
        DomainAuthorization.objects.create(
            domain=d, auth_type="owner",
            authorized_at=timezone.localdate(), authorized_by="admin",
        )
        return d

    def test_past_scheduled_at_rejected(self, user):
        self._authorized_domain()
        past = (timezone.now() - datetime.timedelta(days=1)).isoformat()
        resp = Client().post(
            "/api/scans/start/",
            data='{"domain":"sch.com","schedule_type":"once","scheduled_at":"%s"}' % past,
            content_type="application/json", **_bearer(user),
        )
        assert resp.status_code == 400
        assert "future" in resp.json()["error"]["message"].lower()

    def test_future_scheduled_at_accepted(self, user):
        self._authorized_domain("fut.com")
        future = (timezone.now() + datetime.timedelta(days=1)).isoformat()
        resp = Client().post(
            "/api/scans/start/",
            data='{"domain":"fut.com","schedule_type":"once","scheduled_at":"%s"}' % future,
            content_type="application/json", **_bearer(user),
        )
        assert resp.status_code == 201
