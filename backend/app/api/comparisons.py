from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import record_audit_event
from app.models.models import (
    User, TestCase, DefensivePolicy, TestExecution, ComparisonRecord,
    EvaluationStatus
)
from app.schemas.schemas import ComparisonRequest, ComparisonResponse
from app.services.evaluator import evaluate_test_case

router = APIRouter(prefix="/comparisons", tags=["Before-and-After Comparisons"])

@router.post("/run", response_model=ComparisonResponse)
async def run_comparison(
    req: ComparisonRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes controlled Before-and-After testing on the exact same test case:
    1. Baseline condition (defensive controls disabled).
    2. Protected condition (defensive controls active).
    Detects remediation or regressions.
    """
    stmt = select(TestCase).where(TestCase.id == req.test_case_id)
    res = await db.execute(stmt)
    test_case = res.scalars().first()
    if not test_case:
        raise HTTPException(status_code=404, detail="Test case not found.")

    # Fetch policy
    policy = None
    if req.policy_id:
        p_res = await db.execute(select(DefensivePolicy).where(DefensivePolicy.id == req.policy_id))
        policy = p_res.scalars().first()
    else:
        p_res = await db.execute(select(DefensivePolicy).where(DefensivePolicy.is_default == True))
        policy = p_res.scalars().first()

    # 1. Baseline Run (defenses disabled)
    base_eval = await evaluate_test_case(test_case=test_case, policy=None, baseline_mode=True)
    baseline_exec = TestExecution(
        execution_id=f"BASE-{test_case.test_id[-6:]}",
        test_case_id=test_case.id,
        policy_id=None,
        model_name=base_eval["model_name"],
        baseline_mode=True,
        execution_mode="BASELINE_EVALUATION",
        status=base_eval["status"],
        input_sent=base_eval["input_sent"],
        model_raw_response=base_eval["model_raw_response"],
        evaluation_reasoning=base_eval["evaluation_reasoning"],
        policy_action=base_eval["policy_action"],
        failed_checks=base_eval["failed_checks"],
        confidence_score=base_eval["confidence_score"],
        execution_time_ms=base_eval["execution_time_ms"],
        executed_by_id=current_user.id,
        team=current_user.role
    )
    db.add(baseline_exec)
    await db.commit()
    await db.refresh(baseline_exec)

    # 2. Protected Run (defenses enabled)
    prot_eval = await evaluate_test_case(test_case=test_case, policy=policy, baseline_mode=False)
    protected_exec = TestExecution(
        execution_id=f"PROT-{test_case.test_id[-6:]}",
        test_case_id=test_case.id,
        policy_id=policy.id if policy else None,
        model_name=prot_eval["model_name"],
        baseline_mode=False,
        execution_mode="PROTECTED_EVALUATION",
        status=prot_eval["status"],
        input_sent=prot_eval["input_sent"],
        model_raw_response=prot_eval["model_raw_response"],
        evaluation_reasoning=prot_eval["evaluation_reasoning"],
        policy_action=prot_eval["policy_action"],
        failed_checks=prot_eval["failed_checks"],
        confidence_score=prot_eval["confidence_score"],
        execution_time_ms=prot_eval["execution_time_ms"],
        executed_by_id=current_user.id,
        team=current_user.role
    )
    db.add(protected_exec)
    await db.commit()
    await db.refresh(protected_exec)

    # Analyze change
    base_st = baseline_exec.status.value
    prot_st = protected_exec.status.value
    regression = False

    if base_st == "FAILED" and prot_st == "PASSED":
        status_change = "FAILED -> PASSED (Threat Neutralized / Remediated)"
    elif base_st == "PASSED" and prot_st == "PASSED":
        status_change = "PASSED -> PASSED (Consistently Safe)"
    elif base_st == "PASSED" and prot_st == "FAILED":
        status_change = "PASSED -> FAILED (Regression Detected)"
        regression = True
    elif base_st == "FAILED" and prot_st == "FAILED":
        status_change = "FAILED -> FAILED (Unmitigated Residual Risk)"
    else:
        status_change = f"{base_st} -> {prot_st}"

    comp_record = ComparisonRecord(
        name=req.name,
        test_case_id=test_case.id,
        baseline_execution_id=baseline_exec.id,
        protected_execution_id=protected_exec.id,
        status_change=status_change,
        regression_detected=regression,
        notes=f"Policy evaluated: {policy.name if policy else 'Default'}. Policy action: {prot_eval['policy_action']}.",
        created_by_id=current_user.id
    )

    db.add(comp_record)
    await db.commit()
    await db.refresh(comp_record)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="BEFORE_AFTER_COMPARISON_RUN",
        resource_type="COMPARISON",
        resource_id=str(comp_record.id),
        team_context=current_user.role.value,
        outcome="SUCCESS",
        details={
            "test_case": test_case.test_id,
            "status_change": status_change,
            "regression": regression
        }
    )

    return ComparisonResponse.model_validate(comp_record)

@router.get("", response_model=List[ComparisonResponse])
async def list_comparisons(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(ComparisonRecord).order_by(ComparisonRecord.id.desc())
    res = await db.execute(stmt)
    records = res.scalars().all()
    return [ComparisonResponse.model_validate(r) for r in records]
