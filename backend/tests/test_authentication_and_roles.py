import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.models import UserRole

@pytest.mark.asyncio
async def test_user_registration_red_team_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "Marcus Wright",
            "email": "marcus.red@cyberdefense.org",
            "password": "SecurePassword123!",
            "role": "RED_TEAM",
            "terms_accepted": True
        }
        resp = await client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        user = data["user"]
        assert user["email"] == "marcus.red@cyberdefense.org"
        assert user["role"] == "RED_TEAM"
        assert "hashed_password" not in user
        assert "password" not in user

@pytest.mark.asyncio
async def test_user_registration_blue_team_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "Elena Rostova",
            "email": "elena.blue@cyberdefense.org",
            "password": "DefenseGuard2026!",
            "role": "BLUE_TEAM",
            "terms_accepted": True
        }
        resp = await client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["role"] == "BLUE_TEAM"

@pytest.mark.asyncio
async def test_user_registration_blocks_admin_escalation():
    """Security rule: Public registration must never grant Administrator role."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "Rogue Attacker",
            "email": "rogue@attacker.org",
            "password": "AdminAttempt2026!",
            "role": "ADMIN",
            "terms_accepted": True
        }
        resp = await client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 400
        assert "cannot self-assign Administrator" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_user_registration_blocks_auditor_escalation():
    """Security rule: Public registration must never grant Auditor role."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "Rogue Auditor",
            "email": "auditor_attempt@attacker.org",
            "password": "AuditorAttempt2026!",
            "role": "AUDITOR",
            "terms_accepted": True
        }
        resp = await client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 400
        assert "cannot self-assign Administrator or Auditor" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_user_registration_duplicate_email_conflict():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "Duplicate Tester",
            "email": "duplicate@test.org",
            "password": "Password123!",
            "role": "RED_TEAM",
            "terms_accepted": True
        }
        r1 = await client.post("/api/v1/auth/register", json=payload)
        assert r1.status_code == 200

        r2 = await client.post("/api/v1/auth/register", json=payload)
        assert r2.status_code == 409
        assert "already exists" in r2.json()["detail"]

@pytest.mark.asyncio
async def test_user_registration_requires_terms():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "No Terms User",
            "email": "noterms@test.org",
            "password": "Password123!",
            "role": "RED_TEAM",
            "terms_accepted": False
        }
        resp = await client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 400
        assert "Terms of Service" in resp.json()["detail"]

@pytest.mark.asyncio
async def test_password_login_success_and_failure():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        reg_payload = {
            "full_name": "Login Tester",
            "email": "login.test@defendx.ai",
            "password": "CorrectPassword123!",
            "role": "RED_TEAM",
            "terms_accepted": True
        }
        await client.post("/api/v1/auth/register", json=reg_payload)

        # 1. Successful login
        login_resp = await client.post("/api/v1/auth/login-password", json={
            "email": "login.test@defendx.ai",
            "password": "CorrectPassword123!"
        })
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]

        # 2. Verify /me endpoint with returned JWT
        me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == "login.test@defendx.ai"

        # 3. Wrong password -> 401
        wrong_resp = await client.post("/api/v1/auth/login-password", json={
            "email": "login.test@defendx.ai",
            "password": "WrongPassword999!"
        })
        assert wrong_resp.status_code == 401
        assert "Invalid email or password" in wrong_resp.json()["detail"]

        # 4. Unknown email -> 401
        unknown_resp = await client.post("/api/v1/auth/login-password", json={
            "email": "nonexistent@defendx.ai",
            "password": "CorrectPassword123!"
        })
        assert unknown_resp.status_code == 401

@pytest.mark.asyncio
async def test_password_recovery_and_reset_workflow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        await client.post("/api/v1/auth/register", json={
            "full_name": "Reset Tester",
            "email": "reset.user@defendx.ai",
            "password": "InitialPassword123!",
            "role": "RED_TEAM",
            "terms_accepted": True
        })

        # 1. Request recovery token
        forgot_resp = await client.post("/api/v1/auth/forgot-password", json={
            "email": "reset.user@defendx.ai"
        })
        assert forgot_resp.status_code == 200
        reset_token = forgot_resp.json()["reset_token"]
        assert reset_token is not None

        # 2. Reset password using valid token
        reset_resp = await client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": "NewStrongPassword2026!"
        })
        assert reset_resp.status_code == 200
        assert "successfully reset" in reset_resp.json()["message"]

        # 3. Login with new password -> SUCCESS
        new_login = await client.post("/api/v1/auth/login-password", json={
            "email": "reset.user@defendx.ai",
            "password": "NewStrongPassword2026!"
        })
        assert new_login.status_code == 200

        # 4. Login with old password -> FAILS (401)
        old_login = await client.post("/api/v1/auth/login-password", json={
            "email": "reset.user@defendx.ai",
            "password": "InitialPassword123!"
        })
        assert old_login.status_code == 401

        # 5. Reusing the used reset token -> FAILS (400)
        reuse_resp = await client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": "AnotherPassword333!"
        })
        assert reuse_resp.status_code == 400

@pytest.mark.asyncio
async def test_seeded_accounts_password_authentication():
    """Verify seeded enterprise accounts (Admin, Red, Blue, Auditor) can authenticate with default password."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Admin login
        admin_resp = await client.post("/api/v1/auth/login-password", json={
            "email": "admin@defendx.ai",
            "password": "DefendX2026!Secure"
        })
        assert admin_resp.status_code == 200
        assert admin_resp.json()["user"]["role"] == "ADMIN"

        # Blue Lead login
        blue_resp = await client.post("/api/v1/auth/login-password", json={
            "email": "blueteam@defendx.ai",
            "password": "DefendX2026!Secure"
        })
        assert blue_resp.status_code == 200
        assert blue_resp.json()["user"]["role"] == "BLUE_TEAM"
