import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.config import settings
from app.core.audit import verify_audit_chain, record_audit_event
from app.models.models import AuditEvent, UserRole
from app.services.scanner import scan_file_content
from tests.conftest import TestingSessionLocal
import tempfile
import os

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "HEALTHY"

@pytest.mark.asyncio
async def test_dev_authentication_and_roles():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login as Red Team
        resp = await client.post("/api/v1/auth/login", json={"email": "red@defendx.ai", "role": "RED_TEAM"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["role"] == "RED_TEAM"
        token = data["access_token"]

        # 2. Check /me
        me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == "red@defendx.ai"

@pytest.mark.asyncio
async def test_cross_team_access_denial_and_audit():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Red Team user
        red_token = (await client.post("/api/v1/auth/login", json={"email": "red@defendx.ai", "role": "RED_TEAM"})).json()["access_token"]
        
        # Red Team attempts to create Blue Team policy -> Should be DENIED (403)
        resp = await client.post(
            "/api/v1/blue-team/policies",
            json={
                "name": "Malicious Blue Override Attempt",
                "forbidden_keywords": "none",
                "prompt_injection_threshold": 0.9
            },
            headers={"Authorization": f"Bearer {red_token}"}
        )
        assert resp.status_code == 403
        assert "Access denied" in resp.json()["detail"]

        # Verify audit log recorded the denied attempt
        audit_resp = await client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {red_token}"})
        assert audit_resp.status_code == 200
        events = audit_resp.json()
        unauth_events = [e for e in events if e["action"] == "UNAUTHORIZED_ENDPOINT_ACCESS_ATTEMPT"]
        assert len(unauth_events) > 0
        assert unauth_events[0]["outcome"] == "DENIED"

@pytest.mark.asyncio
async def test_controlled_evaluation_and_policy_protection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        red_token = (await client.post("/api/v1/auth/login", json={"email": "red@defendx.ai", "role": "RED_TEAM"})).json()["access_token"]
        
        # 1. Run Baseline (Defenses Disabled) on Prompt Injection Test
        base_resp = await client.post(
            "/api/v1/evaluation/run",
            json={"test_case_id": 1, "baseline_mode": True},
            headers={"Authorization": f"Bearer {red_token}"}
        )
        assert base_resp.status_code == 200
        base_data = base_resp.json()
        assert base_data["baseline_mode"] is True
        assert base_data["status"] == "FAILED"  # Vulnerability exposed under baseline

        # 2. Run Protected (Defenses Active) on Prompt Injection Test
        prot_resp = await client.post(
            "/api/v1/evaluation/run",
            json={"test_case_id": 1, "baseline_mode": False},
            headers={"Authorization": f"Bearer {red_token}"}
        )
        assert prot_resp.status_code == 200
        prot_data = prot_resp.json()
        assert prot_data["baseline_mode"] is False
        assert prot_data["status"] == "PASSED"  # Attack neutralized by Blue Team guardrail
        assert prot_data["policy_action"] == "BLOCK"

@pytest.mark.asyncio
async def test_before_and_after_comparison():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        red_token = (await client.post("/api/v1/auth/login", json={"email": "red@defendx.ai", "role": "RED_TEAM"})).json()["access_token"]
        
        comp_resp = await client.post(
            "/api/v1/comparisons/run",
            json={"name": "Baseline vs Protected Comparison Suite", "test_case_id": 1},
            headers={"Authorization": f"Bearer {red_token}"}
        )
        assert comp_resp.status_code == 200
        data = comp_resp.json()
        assert "FAILED -> PASSED" in data["status_change"]
        assert data["regression_detected"] is False

@pytest.mark.asyncio
async def test_cryptographic_audit_chain_and_tamper_detection():
    async with TestingSessionLocal() as session:
        # Initial chain must be verified
        res = await verify_audit_chain(session)
        assert res["verified"] is True
        assert res["status"] == "CHAIN_INTEGRITY_VERIFIED"

        # Simulate tampering: directly alter an event's action without updating hashes
        stmt = await session.execute(AuditEvent.__table__.select().limit(1))
        first_row = stmt.first()
        assert first_row is not None
        
        # Tamper with event details in raw query
        await session.execute(
            AuditEvent.__table__.update().where(AuditEvent.id == first_row.id).values(action="TAMPERED_ACTION_MALICIOUS")
        )
        await session.commit()

        # Re-verify -> Tamper should be immediately detected!
        tamper_res = await verify_audit_chain(session)
        assert tamper_res["verified"] is False
        assert tamper_res["status"] == "TAMPER_DETECTED"

@pytest.mark.asyncio
async def test_file_scanner_security():
    # 1. Test invalid extension
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"MZfakebinarycontent")
        bad_path = f.name
    try:
        res = scan_file_content(bad_path, "malware.exe")
        assert res["status"] == "REJECTED"
        assert res["quarantined"] is True
    finally:
        os.remove(bad_path)

    # 2. Test canary secret detection in text
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"Normal log content CANARY-SECRET-8A2F91C4 ending")
        canary_path = f.name
    try:
        res = scan_file_content(canary_path, "logs.txt")
        assert res["status"] == "SUSPICIOUS"
        assert any("Canary" in f for f in res["findings"])
    finally:
        os.remove(canary_path)

def test_alembic_migration_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    alembic_cfg = Config("alembic.ini")
    script = ScriptDirectory.from_config(alembic_cfg)
    heads = script.get_heads()
    assert len(heads) == 1
    assert heads[0] == "dd083ff9997d"

