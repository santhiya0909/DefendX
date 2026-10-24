from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import require_roles
from app.core.audit import record_audit_event
from app.models.models import User, UserRole
from app.schemas.schemas import UserResponse, UserUpdate

router = APIRouter(prefix="/users", tags=["User Management"])

@router.get("", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    """Admin-only: Retrieve all registered users and roles."""
    stmt = select(User).order_by(User.id.asc())
    res = await db.execute(stmt)
    users = res.scalars().all()
    return [UserResponse.model_validate(u) for u in users]

@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    req: UserUpdate,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    """Admin-only: Update user role or account status."""
    stmt = select(User).where(User.id == user_id)
    res = await db.execute(stmt)
    target_user = res.scalars().first()

    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if req.role:
        target_user.role = req.role
    if req.status:
        target_user.status = req.status
    if req.full_name:
        target_user.full_name = req.full_name

    await db.commit()
    await db.refresh(target_user)

    await record_audit_event(
        db=db,
        actor_id=str(admin_user.id),
        actor_role=admin_user.role.value,
        action="USER_ROLE_OR_STATUS_UPDATE",
        resource_type="USER",
        resource_id=str(target_user.id),
        team_context=admin_user.role.value,
        outcome="SUCCESS",
        details={"updated_role": target_user.role.value, "updated_status": target_user.status.value}
    )

    return UserResponse.model_validate(target_user)
