"""Tests for DomainAuthorization model, API serialization, and scan gate."""

import datetime
import json
import pytest
from django.contrib.auth.models import User
from ninja_jwt.tokens import AccessToken


def post_json(client, path, data):
    return client.post(path, data=json.dumps(data), content_type="application/json")


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainAuthorizationModel:
    def test_create_and_retrieve_via_related_name(self, domain):
        from apps.core.domains.models import DomainAuthorization
        auth = DomainAuthorization.objects.create(
            domain=domain,
            auth_type="owner",
            authorized_at=datetime.date(2026, 1, 15),
            authorized_by="Alice Smith",
            auth_reference="https://whois.example.com/example.com",
        )
        assert domain.authorization == auth
        assert auth.auth_type == "owner"
        assert auth.authorized_by == "Alice Smith"

    def test_cascade_delete(self, domain):
        from apps.core.domains.models import DomainAuthorization
        DomainAuthorization.objects.create(
            domain=domain,
            auth_type="owner",
            authorized_at=datetime.date(2026, 1, 15),
            authorized_by="Alice Smith",
        )
        assert DomainAuthorization.objects.count() == 1
        domain.delete()
        assert DomainAuthorization.objects.count() == 0

    def test_auth_reference_optional(self, domain):
        from apps.core.domains.models import DomainAuthorization
        auth = DomainAuthorization(
            domain=domain,
            auth_type="bug_bounty",
            authorized_at=datetime.date(2026, 3, 1),
            authorized_by="HackerOne Program",
            auth_reference="",
        )
        auth.full_clean()  # blank=True means this must not raise
        auth.save()
        assert auth.pk is not None

    def test_str_includes_domain_and_type(self, domain):
        from apps.core.domains.models import DomainAuthorization
        auth = DomainAuthorization.objects.create(
            domain=domain,
            auth_type="written_consent",
            authorized_at=datetime.date(2026, 2, 1),
            authorized_by="Legal Team",
        )
        assert "example.com" in str(auth)
        assert "Written Consent" in str(auth)


# ---------------------------------------------------------------------------
# API serialization tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainSerializationAuthorization:
    def test_domain_with_authorization_includes_auth_object(self, auth_client, domain):
        from apps.core.domains.models import DomainAuthorization
        DomainAuthorization.objects.create(
            domain=domain,
            auth_type="owner",
            authorized_at=datetime.date(2026, 1, 15),
            authorized_by="Alice Smith",
            auth_reference="https://example.com/auth.pdf",
        )
        resp = auth_client.get("/api/domains/")
        assert resp.status_code == 200
        domains = resp.json()
        assert len(domains) == 1
        auth = domains[0]["authorization"]
        assert auth is not None
        assert auth["auth_type"] == "owner"
        assert auth["auth_type_display"] == "Domain Owner"
        assert auth["authorized_by"] == "Alice Smith"
        assert auth["authorized_at"] == "2026-01-15"
        assert auth["auth_reference"] == "https://example.com/auth.pdf"

    def test_domain_without_authorization_returns_null(self, auth_client, domain):
        resp = auth_client.get("/api/domains/")
        assert resp.status_code == 200
        domains = resp.json()
        assert len(domains) == 1
        assert domains[0]["authorization"] is None
