import pytest
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.config import settings
from app.models.models import UserRole

@pytest.mark.asyncio
async def test_auth_config_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/auth/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "google_oauth_configured" in data
        assert "google_client_id_configured" in data
        assert "dev_auth_enabled" in data
        assert "environment" in data

@pytest.mark.asyncio
async def test_google_login_missing_credential():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/auth/google", json={"credential": ""})
        assert resp.status_code == 400
        assert "Missing Google OAuth credential token" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_google_login_unconfigured_backend():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch.object(settings, "GOOGLE_CLIENT_ID", ""):
            resp = await client.post("/api/v1/auth/google", json={"credential": "sample.jwt.token"})
            assert resp.status_code == 501
            assert "Google OAuth is not configured" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_google_login_invalid_token():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch.object(settings, "GOOGLE_CLIENT_ID", "test-google-client-id.apps.googleusercontent.com"):
            resp = await client.post("/api/v1/auth/google", json={"credential": "invalid-garbage-token"})
            assert resp.status_code == 401
            assert "Google token verification failed" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_google_login_unverified_email():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch.object(settings, "GOOGLE_CLIENT_ID", "test-google-client-id.apps.googleusercontent.com"):
            mock_idinfo = {
                "iss": "accounts.google.com",
                "aud": "test-google-client-id.apps.googleusercontent.com",
                "email": "unverified@example.com",
                "email_verified": False,
                "name": "Unverified User",
            }
            with patch("google.oauth2.id_token.verify_oauth2_token", return_value=mock_idinfo):
                resp = await client.post("/api/v1/auth/google", json={"credential": "mocked.valid.jwt"})
                assert resp.status_code == 403
                assert "Unverified Google email address" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_google_login_success_and_least_privilege_enforcement():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch.object(settings, "GOOGLE_CLIENT_ID", "test-google-client-id.apps.googleusercontent.com"):
            mock_idinfo = {
                "iss": "accounts.google.com",
                "aud": "test-google-client-id.apps.googleusercontent.com",
                "email": "researcher@example.com",
                "email_verified": True,
                "name": "Safety Researcher",
                "picture": "https://lh3.googleusercontent.com/a/avatar123",
            }
            with patch("google.oauth2.id_token.verify_oauth2_token", return_value=mock_idinfo):
                resp = await client.post("/api/v1/auth/google", json={"credential": "mocked.valid.jwt"})
                assert resp.status_code == 200
                data = resp.json()
                assert "access_token" in data
                user_info = data["user"]
                assert user_info["email"] == "researcher@example.com"
                assert user_info["full_name"] == "Safety Researcher"
                assert user_info["auth_provider"] == "google"
                # Strict least privilege check: new Google accounts must NOT get ADMIN
                assert user_info["role"] == UserRole.RED_TEAM.value

                # Verify token can access protected endpoints
                token = data["access_token"]
                me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
                assert me_resp.status_code == 200
                assert me_resp.json()["email"] == "researcher@example.com"

@pytest.mark.asyncio
async def test_dev_login_blocked_in_production():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch.object(settings, "ENVIRONMENT", "production"):
            resp = await client.post("/api/v1/auth/login", json={"email": "attacker@evil.com", "role": "ADMIN"})
            assert resp.status_code == 403
            assert "Development login is strictly disabled in production" in resp.json()["detail"]
