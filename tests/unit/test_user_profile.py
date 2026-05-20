"""Unit tests for UserProfile model and auto-creation signal."""

import pytest
from django.contrib.auth import get_user_model

from apps.core.dashboard.models import UserProfile

User = get_user_model()


@pytest.mark.django_db
class TestUserProfileModel:
    def test_profile_auto_created_on_user_creation(self):
        user = User.objects.create_user(username="newuser", password="pass123")
        assert UserProfile.objects.filter(user=user).exists()

    def test_must_change_password_defaults_to_false(self):
        user = User.objects.create_user(username="newuser2", password="pass123")
        assert user.profile.must_change_password is False

    def test_profile_deleted_when_user_deleted(self):
        user = User.objects.create_user(username="todelete", password="pass123")
        profile_id = user.profile.pk
        user.delete()
        assert not UserProfile.objects.filter(pk=profile_id).exists()

    def test_str_representation(self):
        user = User.objects.create_user(username="struser", password="pass123")
        assert str(user.profile) == "Profile(struser)"

    def test_can_set_must_change_password(self):
        user = User.objects.create_user(username="flaguser", password="pass123")
        profile = user.profile
        profile.must_change_password = True
        profile.save()
        profile.refresh_from_db()
        assert profile.must_change_password is True

    def test_get_or_create_does_not_duplicate(self):
        user = User.objects.create_user(username="dupuser", password="pass123")
        # Signal already created one; get_or_create should not create another
        profile, created = UserProfile.objects.get_or_create(user=user)
        assert not created
        assert UserProfile.objects.filter(user=user).count() == 1

    def test_profile_is_accessible_via_related_name(self):
        user = User.objects.create_user(username="reluser", password="pass123")
        assert hasattr(user, "profile")
        assert isinstance(user.profile, UserProfile)
