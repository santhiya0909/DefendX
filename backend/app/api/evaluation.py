import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import record_audit_event
from app.models.models import (
    User, TestCase, DefensivePolicy, TestExecution, SecurityFinding,
    EvaluationStatus, FindingStatus
)
from app.schemas.schemas import ExecutionRequest, TestExecutionResponse
from app.services.evaluator import evaluate_test_case

router = APIRouter(prefix="/evaluation", tags=["Controlled Evaluation Engine"])

@router.post("/run", response_model=TestExecutionResponse)
async def run_evaluation(
    req: ExecutionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes an approved test case through the controlled AI evaluation engine.
    Applies input guardrails, controlled model interface, and output verification.
    """
    # Fetch test case
    stmt = select(TestCase).where(TestCase.id == req.test_case_id)
    res = await db.execute(stmt)
    test_case = res.scalars().first()
    if not test_case:
        raise HTTPException(status_code=404, detail="Test case not found.")

    # Fetch policy if specified or pick default
    policy = None
    if not req.baseline_mode:
        if req.policy_id:
            p_stmt = select(DefensivePolicy).where(DefensivePolicy.id == req.policy_id)
            p_res = await db.execute(p_stmt)
            policy = p_res.scalars().first()
        else:
            p_stmt = select(DefensivePolicy).where(DefensivePolicy.is_default == True)
            p_res = await db.execute(p_stmt)
            policy = p_res.scalars().first()

    # Execute controlled evaluation
    eval_result = await evaluate_test_case(
        test_case=test_case,
        policy=policy,
        baseline_mode=req.baseline_mode,
        model_override=req.model_override
    )

    execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
    execution = TestExecution(
        execution_id=execution_id,
        test_case_id=test_case.id,
        policy_id=policy.id if policy else None,
        model_name=eval_result["model_name"],
        baseline_mode=req.baseline_mode,
        execution_mode=req.execution_mode,
        status=eval_result["status"],
        input_sent=eval_result["input_sent"],
        model_raw_response=eval_result["model_raw_response"],
        evaluation_reasoning=eval_result["evaluation_reasoning"],
        policy_action=eval_result["policy_action"],
        failed_checks=eval_result["failed_checks"],
        confidence_score=eval_result["confidence_score"],
        execution_time_ms=eval_result["execution_time_ms"],
        executed_by_id=current_user.id,
        team=current_user.role
    )

    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    # If test failed, create or link a Security Finding
    if eval_result["status"] == EvaluationStatus.FAILED:
        finding_code = f"FIND-{test_case.category.value[:4]}-{uuid.uuid4().hex[:6].upper()}"
        finding = SecurityFinding(
            finding_code=finding_code,
            title=f"Vulnerability: {test_case.name}",
            description=eval_result["evaluation_reasoning"],
            category=test_case.category,
            severity=test_case.severity,
            affected_component=f"Model: {eval_result['model_name']} / Policy: {policy.name if policy else 'None (Baseline)'}",
            test_execution_id=execution.id,
            detection_method="DefendX Adversarial Safety Suite",
            confidence=eval_result["confidence_score"],
            reproducibility_status="REPRODUCIBLE",
            remediation_recommendation=(
                "Update Blue Team input filter keywords or enable output guardrail "
                "regex containment to neutralize this threat pattern."
            ),
            status=FindingStatus.CONFIRMED if req.baseline_mode else FindingStatus.OPEN,
            owner_id=current_user.id,
            team=current_user.role
        )
        db.add(finding)
        await db.commit()

    # Record Audit Event
    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="EVALUATION_EXECUTION_COMPLETED",
        resource_type="TEST_EXECUTION",
        resource_id=execution.execution_id,
        team_context=current_user.role.value,
        outcome="SUCCESS" if eval_result["status"] == EvaluationStatus.PASSED else "FAILURE_DETECTED",
        details={
            "test_case_id": test_case.test_id,
            "status": eval_result["status"].value,
            "baseline_mode": req.baseline_mode,
            "policy_action": eval_result["policy_action"]
        }
    )

    return TestExecutionResponse.model_validate(execution)

@router.get("/results", response_model=List[TestExecutionResponse])
async def list_evaluation_results(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(TestExecution).order_by(TestExecution.id.desc()).limit(limit)
    res = await db.execute(stmt)
    records = res.scalars().all()
    return [TestExecutionResponse.model_validate(r) for r in records]
