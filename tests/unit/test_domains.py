"""Unit tests for apps/domains — model and views."""

import pytest
from django.urls import reverse


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainModel:
    def test_create_primary_domain(self):
        from apps.domains.models import Domain
        d = Domain.objects.create(name="cybersecify.com", is_primary=True)
        assert d.is_primary is True
        assert d.is_active is True  # default

    def test_create_related_domain(self):
        from apps.domains.models import Domain
        d = Domain.objects.create(name="cybersecify.in", is_primary=False)
        assert d.is_primary is False

    def test_domain_name_unique(self):
        from apps.domains.models import Domain
        from django.db import IntegrityError
        Domain.objects.create(name="unique.com")
        with pytest.raises(IntegrityError):
            Domain.objects.create(name="unique.com")

    def test_str_representation(self):
        from apps.domains.models import Domain
        d = Domain.objects.create(name="test.com")
        assert "test.com" in str(d)

    def test_toggle_active(self, domain):
        domain.is_active = False
        domain.save()
        domain.refresh_from_db()
        assert domain.is_active is False


# ---------------------------------------------------------------------------
# View tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainViews:
    def test_domain_list_requires_login(self, client):
        resp = client.get(reverse("domain-list"))
        assert resp.status_code == 302
        assert "/accounts/login/" in resp["Location"]

    def test_domain_list_authenticated(self, auth_client, domain):
        resp = auth_client.get(reverse("domain-list"))
        assert resp.status_code == 200
        assert b"example.com" in resp.content

    def test_add_domain_post(self, auth_client):
        from apps.domains.models import Domain
        resp = auth_client.post(reverse("domain-list"), {
            "name": "newdomain.com",
            "is_primary": False,
        })
        assert resp.status_code == 302
        assert Domain.objects.filter(name="newdomain.com").exists()

    def test_add_duplicate_domain_shows_error(self, auth_client, domain):
        resp = auth_client.post(reverse("domain-list"), {
            "name": "example.com",
            "is_primary": False,
        })
        assert resp.status_code == 200  # re-renders form with error
        assert b"example.com" in resp.content

    def test_toggle_domain(self, auth_client, domain):
        from apps.domains.models import Domain
        assert domain.is_active is True
        auth_client.post(reverse("domain-toggle", args=[domain.pk]))
        domain.refresh_from_db()
        assert domain.is_active is False

    def test_delete_domain_removes_scan_data(self, auth_client, domain, completed_session, domain_finding):
        from apps.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding

        assert ScanSession.objects.filter(domain="example.com").exists()
        assert DomainFinding.objects.filter(domain="example.com").exists()

        auth_client.post(reverse("domain-delete", args=[domain.pk]))

        assert not ScanSession.objects.filter(domain="example.com").exists()
        assert not DomainFinding.objects.filter(domain="example.com").exists()

    def test_delete_domain_removes_domain_record(self, auth_client, domain):
        from apps.domains.models import Domain
        auth_client.post(reverse("domain-delete", args=[domain.pk]))
        assert not Domain.objects.filter(pk=domain.pk).exists()
