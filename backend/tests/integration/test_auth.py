"""Integration tests for the auth flow + RBAC enforcement."""

import pytest


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_success_returns_tokens(self, client, admin_user):
        user, plain = admin_user
        res = await client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": plain},
        )
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_wrong_password_rejected(self, client, admin_user):
        user, _ = admin_user
        res = await client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": "wrong-password!"},
        )
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_login_unknown_email_rejected(self, client):
        res = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@nowhere.local", "password": "whatever-pass-12"},
        )
        assert res.status_code == 401


class TestMe:
    @pytest.mark.asyncio
    async def test_me_requires_auth(self, client):
        res = await client.get("/api/v1/auth/me")
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_me_returns_current_user(self, client, admin_token, admin_user):
        user, _ = admin_user
        res = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res.status_code == 200
        body = res.json()
        assert body["email"] == user.email
        assert body["role"] == "admin"


class TestRBAC:
    @pytest.mark.asyncio
    async def test_auditor_cannot_create_engagement(self, client, auditor_token):
        res = await client.post(
            "/api/v1/engagements",
            json={"client_name": "Acme", "code": "TST-001"},
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert res.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_create_engagement(self, client, admin_token):
        res = await client.post(
            "/api/v1/engagements",
            json={"client_name": "Acme Corp", "code": "TST-002"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 201
        body = res.json()
        assert body["client_name"] == "Acme Corp"
        assert body["code"] == "TST-002"
