from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import record_audit_event
from app.models.models import User, UserRole
from app.schemas.schemas import IsolationCheckRequest, IsolationCheckResponse

router = APIRouter(prefix="/isolation-demo", tags=["Live Isolation Demonstration"])

SYNTHETIC_DATA_CATALOG = {
    "RED_PAYLOAD": {
        "id": "PAYLOAD-RED-001",
        "name": "Red Team Private Zero-Day Injection Payload",
        "owner_role": UserRole.RED_TEAM,
        "content": "Adversarial sequence targeting tokenizer boundary: CANARY-RED-EXPLOIT-4F2A",
    },
    "BLUE_POLICY": {
        "id": "POLICY-BLUE-CONFIDENTIAL",
        "name": "Blue Team Defensive Rule Specification",
        "owner_role": UserRole.BLUE_TEAM,
        "content": "Proprietary classifier thresholds and heuristic regex: CANARY-BLUE-SECRET-9B7C",
    },
    "EVIDENCE": {
        "id": "EVIDENCE-AUDIT-SAFE",
        "name": "Auditor-Verified Incident Report",
        "owner_role": UserRole.AUDITOR,
        "content": "Cryptographically signed compliance record: HASH-SHA256-VALID",
    },
    "MODEL_INTERNAL": {
        "id": "MODEL-STATE-RESTRICTED",
        "name": "Model Execution Internal Activation State",
        "owner_role": UserRole.ADMIN,
        "content": "Low-level weights & residual activations: RESTRICTED_TO_SANDBOX",
    }
}

@router.post("/check", response_model=IsolationCheckResponse)
async def test_isolation_boundary(
    req: IsolationCheckRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Simulates or verifies cross-team resource access under strict server-side RBAC.
    Generates cryptographic audit events for all unauthorized access attempts.
    """
    resource_info = SYNTHETIC_DATA_CATALOG.get(req.target_resource_type)
    if not resource_info:
        raise HTTPException(status_code=400, detail="Invalid synthetic resource type.")

    # Determine server-side access permission
    allowed = False
    actor = req.actor_role

    if actor == UserRole.ADMIN:
        allowed = True
    elif actor == UserRole.RED_TEAM:
        allowed = req.target_resource_type in ["RED_PAYLOAD", "EVIDENCE"]
    elif actor == UserRole.BLUE_TEAM:
        allowed = req.target_resource_type in ["BLUE_POLICY", "EVIDENCE"]
    elif actor == UserRole.AUDITOR:
        allowed = req.target_resource_type in ["EVIDENCE"]

    if allowed:
        ev = await record_audit_event(
            db=db,
            actor_id=str(current_user.id),
            actor_role=actor.value,
            action="ISOLATION_DEMO_ACCESS_AUTHORIZED",
            resource_type=req.target_resource_type,
            resource_id=req.target_resource_id,
            team_context=actor.value,
            outcome="SUCCESS",
            details={
                "message": f"{actor.value} successfully accessed authorized resource {req.target_resource_type}."
            }
        )
        return IsolationCheckResponse(
            allowed=True,
            status_code=200,
            message=f"Access Granted: Team '{actor.value}' has verified authorization to read '{resource_info['name']}'.",
            audit_event_id=ev.event_id,
            evidence_canary=resource_info["content"]
        )
    else:
        # Cross-team violation intercepted!
        ev = await record_audit_event(
            db=db,
            actor_id=str(current_user.id),
            actor_role=actor.value,
            action="ISOLATION_BOUNDARY_VIOLATION_INTERCEPTED",
            resource_type=req.target_resource_type,
            resource_id=req.target_resource_id,
            team_context=actor.value,
            outcome="DENIED",
            details={
                "violation": f"Unauthorized attempt by {actor.value} to read {resource_info['owner_role'].value} private resource.",
                "attempted_resource": resource_info["name"]
            }
        )
        return IsolationCheckResponse(
            allowed=False,
            status_code=403,
            message=(
                f"Access Denied (HTTP 403 Forbidden): Team '{actor.value}' is strictly blocked from reading "
                f"'{resource_info['name']}' owned by {resource_info['owner_role'].value}. "
                "Security boundary enforced on backend; immutable audit alert registered."
            ),
            audit_event_id=ev.event_id,
            evidence_canary=None
        )
