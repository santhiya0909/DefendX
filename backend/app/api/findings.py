from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import record_audit_event
from app.models.models import User, SecurityFinding, Severity, TestCategory, FindingStatus
from app.schemas.schemas import FindingResponse, FindingUpdate

router = APIRouter(prefix="/findings", tags=["Security Findings and Risk Analysis"])

@router.get("", response_model=List[FindingResponse])
async def list_findings(
    severity: Optional[Severity] = None,
    category: Optional[TestCategory] = None,
    status_filter: Optional[FindingStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(SecurityFinding)
    if severity:
        stmt = stmt.where(SecurityFinding.severity == severity)
    if category:
        stmt = stmt.where(SecurityFinding.category == category)
    if status_filter:
        stmt = stmt.where(SecurityFinding.status == status_filter)

    stmt = stmt.order_by(SecurityFinding.id.desc())
    res = await db.execute(stmt)
    findings = res.scalars().all()
    return [FindingResponse.model_validate(f) for f in findings]

@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    req: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(SecurityFinding).where(SecurityFinding.id == finding_id)
    res = await db.execute(stmt)
    finding = res.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if req.status:
        finding.status = req.status
    if req.remediation_recommendation:
        finding.remediation_recommendation = req.remediation_recommendation
    if req.owner_id:
        finding.owner_id = req.owner_id

    await db.commit()
    await db.refresh(finding)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="UPDATE_SECURITY_FINDING_STATUS",
        resource_type="SECURITY_FINDING",
        resource_id=finding.finding_code,
        team_context=current_user.role.value,
        outcome="SUCCESS",
        details={"new_status": finding.status.value}
    )

    return FindingResponse.model_validate(finding)
