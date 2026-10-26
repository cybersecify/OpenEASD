"""Unit tests for apps/domains — model logic."""

import pytest


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainModel:
    def test_create_primary_domain(self):
        from apps.core.data.domains.models import Domain
        d = Domain.objects.create(name="cybersecify.com", is_primary=True)
        assert d.is_primary is True
        assert d.is_active is True  # default

    def test_create_related_domain(self):
        from apps.core.data.domains.models import Domain
        d = Domain.objects.create(name="example.org", is_primary=False)
        assert d.is_primary is False

    def test_domain_name_unique(self):
        from apps.core.data.domains.models import Domain
        from django.db import IntegrityError
        Domain.objects.create(name="unique.com")
        with pytest.raises(IntegrityError):
            Domain.objects.create(name="unique.com")

    def test_str_representation(self):
        from apps.core.data.domains.models import Domain
        d = Domain.objects.create(name="test.com")
        assert "test.com" in str(d)

    def test_toggle_active(self, domain):
        domain.is_active = False
        domain.save()
        domain.refresh_from_db()
        assert domain.is_active is False
