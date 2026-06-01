"""Tests for /api/users/ endpoints."""
import pytest
from django.contrib.auth.models import User
from ninja_jwt.tokens import AccessToken


def _auth(client, user):
    token = str(AccessToken.for_user(user))
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client


@pytest.fixture
def superuser(db):
    return User.objects.create_superuser(username="admin", password="pass123")


@pytest.fixture
def regular_user(db):
    return User.objects.create_user(username="alice", password="pass123")


@pytest.fixture
def admin_client(client, superuser):
    return _auth(client, superuser)


@pytest.fixture
def user_client(client, regular_user):
    return _auth(client, regular_user)


@pytest.mark.django_db
class TestListUsers:
    def test_superuser_can_list(self, admin_client, superuser, regular_user):
        res = admin_client.get("/api/users/")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        assert len(data) == 2
        usernames = {u["username"] for u in data}
        assert "admin" in usernames
        assert "alice" in usernames

    def test_regular_user_gets_403(self, user_client):
        res = user_client.get("/api/users/")
        assert res.status_code == 403

    def test_unauthenticated_gets_401(self, client):
        res = client.get("/api/users/")
        assert res.status_code == 401

    def test_response_shape(self, admin_client, superuser):
        res = admin_client.get("/api/users/")
        user = next(u for u in res.json() if u["username"] == "admin")
        assert "id" in user
        assert "username" in user
        assert "is_superuser" in user
        assert "is_active" in user
        assert "date_joined" in user
        assert "last_login" in user
