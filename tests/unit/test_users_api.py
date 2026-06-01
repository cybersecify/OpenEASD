"""Tests for /api/users/ endpoints."""
import json
import pytest
from django.contrib.auth.models import User
from ninja_jwt.tokens import AccessToken


def post_json(client, path, data):
    return client.post(path, data=json.dumps(data), content_type="application/json")


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


@pytest.mark.django_db
class TestCreateUser:
    def test_creates_user(self, admin_client):
        res = post_json(admin_client, "/api/users/create/", {
            "username": "bob",
            "password": "securepass1",
            "is_superuser": False,
        })
        assert res.status_code == 200
        assert User.objects.filter(username="bob").exists()

    def test_new_user_must_change_password(self, admin_client):
        post_json(admin_client, "/api/users/create/", {
            "username": "bob",
            "password": "securepass1",
            "is_superuser": False,
        })
        u = User.objects.get(username="bob")
        assert u.profile.must_change_password is True

    def test_duplicate_username_returns_400(self, admin_client, regular_user):
        res = post_json(admin_client, "/api/users/create/", {
            "username": "alice",
            "password": "securepass1",
            "is_superuser": False,
        })
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "BAD_REQUEST"

    def test_short_password_returns_400(self, admin_client):
        res = post_json(admin_client, "/api/users/create/", {
            "username": "bob",
            "password": "short",
            "is_superuser": False,
        })
        assert res.status_code == 400

    def test_regular_user_gets_403(self, user_client):
        res = post_json(user_client, "/api/users/create/", {
            "username": "bob",
            "password": "securepass1",
            "is_superuser": False,
        })
        assert res.status_code == 403
