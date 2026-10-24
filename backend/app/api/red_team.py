import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import require_roles
from app.core.audit import record_audit_event
from app.models.models import User, UserRole, TestCase, TestDataset, TestCategory, Severity
from app.schemas.schemas import TestCaseCreate, TestCaseResponse, TestCaseUpdate, TestDatasetResponse

router = APIRouter(prefix="/red-team", tags=["Red Team Workspace"])

@router.get("/test-cases", response_model=List[TestCaseResponse])
async def list_test_cases(
    category: Optional[TestCategory] = None,
    severity: Optional[Severity] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.RED_TEAM, UserRole.ADMIN, UserRole.AUDITOR]))
):
    """
    List test cases.
    Auditors and Admins have read access. Red Team has author access.
    Blue Team is restricted from viewing private adversarial payloads directly.
    """
    stmt = select(TestCase)
    if category:
        stmt = stmt.where(TestCase.category == category)
    if severity:
        stmt = stmt.where(TestCase.severity == severity)
    stmt = stmt.order_by(TestCase.id.desc())

    res = await db.execute(stmt)
    records = res.scalars().all()
    return [TestCaseResponse.model_validate(tc) for tc in records]

@router.post("/test-cases", response_model=TestCaseResponse)
async def create_test_case(
    req: TestCaseCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.RED_TEAM, UserRole.ADMIN]))
):
    """Create a new authorized adversarial test case."""
    test_id = req.test_id or f"TC-{req.category.value[:4]}-{uuid.uuid4().hex[:6].upper()}"

    # Check for duplicate test_id
    existing = await db.execute(select(TestCase).where(TestCase.test_id == test_id))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail=f"Duplicate test ID '{test_id}' already exists.")

    test_case = TestCase(
        test_id=test_id,
        name=req.name,
        description=req.description,
        category=req.category,
        severity=req.severity,
        input_prompt=req.input_prompt,
        expected_behavior=req.expected_behavior,
        tags=req.tags,
        is_sandbox_only=req.is_sandbox_only,
        team=UserRole.RED_TEAM,
        created_by_id=current_user.id
    )

    db.add(test_case)
    await db.commit()
    await db.refresh(test_case)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="CREATE_TEST_CASE",
        resource_type="TEST_CASE",
        resource_id=test_case.test_id,
        team_context=UserRole.RED_TEAM.value,
        outcome="SUCCESS",
        details={"name": test_case.name, "category": test_case.category.value, "severity": test_case.severity.value}
    )

    return TestCaseResponse.model_validate(test_case)

@router.get("/test-cases/{test_id}", response_model=TestCaseResponse)
async def get_test_case(
    test_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.RED_TEAM, UserRole.ADMIN, UserRole.AUDITOR]))
):
    stmt = select(TestCase).where(TestCase.test_id == test_id)
    res = await db.execute(stmt)
    tc = res.scalars().first()
    if not tc:
        raise HTTPException(status_code=404, detail="Test case not found")
    return TestCaseResponse.model_validate(tc)

@router.delete("/test-cases/{test_id}")
async def delete_test_case(
    test_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.RED_TEAM, UserRole.ADMIN]))
):
    stmt = select(TestCase).where(TestCase.test_id == test_id)
    res = await db.execute(stmt)
    tc = res.scalars().first()
    if not tc:
        raise HTTPException(status_code=404, detail="Test case not found")

    await db.delete(tc)
    await db.commit()

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="DELETE_TEST_CASE",
        resource_type="TEST_CASE",
        resource_id=test_id,
        team_context=UserRole.RED_TEAM.value,
        outcome="SUCCESS"
    )
    return {"message": f"Test case {test_id} successfully deleted."}

@router.get("/datasets", response_model=List[TestDatasetResponse])
async def list_datasets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.RED_TEAM, UserRole.ADMIN, UserRole.AUDITOR]))
):
    stmt = select(TestDataset).order_by(TestDataset.id.desc())
    res = await db.execute(stmt)
    datasets = res.scalars().all()
    return [TestDatasetResponse.model_validate(d) for d in datasets]
