import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.core.database import get_db
from app.core.security import require_roles
from app.core.audit import record_audit_event
from app.models.models import User, UserRole, DefensivePolicy
from app.schemas.schemas import (
    DefensivePolicyCreate, DefensivePolicyResponse, DefensivePolicyUpdate
)

router = APIRouter(prefix="/blue-team", tags=["Blue Team Workspace"])

@router.get("/policies", response_model=List[DefensivePolicyResponse])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.BLUE_TEAM, UserRole.ADMIN, UserRole.AUDITOR]))
):
    """List all defensive policies."""
    stmt = select(DefensivePolicy).order_by(DefensivePolicy.id.desc())
    res = await db.execute(stmt)
    policies = res.scalars().all()
    return [DefensivePolicyResponse.model_validate(p) for p in policies]

@router.post("/policies", response_model=DefensivePolicyResponse)
async def create_policy(
    req: DefensivePolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.BLUE_TEAM, UserRole.ADMIN]))
):
    """Create a new defensive policy with configurable input/output filters."""
    policy_id = req.policy_id or f"POL-{uuid.uuid4().hex[:6].upper()}"

    # If is_default, clear other defaults
    if req.is_default:
        await db.execute(update(DefensivePolicy).values(is_default=False))

    policy = DefensivePolicy(
        policy_id=policy_id,
        name=req.name,
        description=req.description,
        is_active=req.is_active,
        is_default=req.is_default,
        input_filter_enabled=req.input_filter_enabled,
        output_filter_enabled=req.output_filter_enabled,
        forbidden_keywords=req.forbidden_keywords,
        canary_protection_enabled=req.canary_protection_enabled,
        prompt_injection_threshold=req.prompt_injection_threshold,
        leak_prevention_regex=req.leak_prevention_regex,
        team=UserRole.BLUE_TEAM,
        version=req.version,
        created_by_id=current_user.id
    )

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="CREATE_DEFENSIVE_POLICY",
        resource_type="DEFENSIVE_POLICY",
        resource_id=policy.policy_id,
        team_context=UserRole.BLUE_TEAM.value,
        outcome="SUCCESS",
        details={"name": policy.name, "threshold": policy.prompt_injection_threshold}
    )

    return DefensivePolicyResponse.model_validate(policy)

@router.patch("/policies/{policy_id}", response_model=DefensivePolicyResponse)
async def update_policy(
    policy_id: str,
    req: DefensivePolicyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.BLUE_TEAM, UserRole.ADMIN]))
):
    stmt = select(DefensivePolicy).where(DefensivePolicy.policy_id == policy_id)
    res = await db.execute(stmt)
    policy = res.scalars().first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    update_data = req.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(policy, field, val)

    await db.commit()
    await db.refresh(policy)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="UPDATE_DEFENSIVE_POLICY",
        resource_type="DEFENSIVE_POLICY",
        resource_id=policy_id,
        team_context=UserRole.BLUE_TEAM.value,
        outcome="SUCCESS",
        details=update_data
    )

    return DefensivePolicyResponse.model_validate(policy)
