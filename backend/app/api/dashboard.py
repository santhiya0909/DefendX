from collections import defaultdict
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import verify_audit_chain
from app.models.models import (
    User, TestExecution, SecurityFinding, UploadedFile, AuditEvent,
    EvaluationStatus, Severity, TestCategory
)
from app.schemas.schemas import DashboardMetricsResponse, AuditEventResponse

router = APIRouter(prefix="/dashboard", tags=["Security Dashboard"])

@router.get("/metrics", response_model=DashboardMetricsResponse)
async def get_dashboard_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Computes real-time dashboard analytics directly from database tables.
    Never uses simulated or fabricated figures.
    """
    # 1. Test Executions
    total_execs = await db.scalar(select(func.count(TestExecution.id))) or 0
    passed_execs = await db.scalar(select(func.count(TestExecution.id)).where(TestExecution.status == EvaluationStatus.PASSED)) or 0
    failed_execs = await db.scalar(select(func.count(TestExecution.id)).where(TestExecution.status == EvaluationStatus.FAILED)) or 0
    inconclusive_execs = await db.scalar(select(func.count(TestExecution.id)).where(TestExecution.status == EvaluationStatus.INCONCLUSIVE)) or 0

    # 2. Specific Security Incidents
    prompt_inj_count = await db.scalar(
        select(func.count(SecurityFinding.id)).where(SecurityFinding.category == TestCategory.PROMPT_INJECTION)
    ) or 0

    leakage_count = await db.scalar(
        select(func.count(SecurityFinding.id)).where(
            SecurityFinding.category.in_([TestCategory.CONTEXT_LEAKAGE, TestCategory.CROSS_TEAM_LEAKAGE, TestCategory.SENSITIVE_INFO])
        )
    ) or 0

    cross_team_violations = await db.scalar(
        select(func.count(AuditEvent.id)).where(AuditEvent.action.ilike("%VIOLATION%"))
    ) or 0

    # 3. File Scanner
    files_scanned = await db.scalar(select(func.count(UploadedFile.id))) or 0
    files_quarantined = await db.scalar(select(func.count(UploadedFile.id)).where(UploadedFile.is_quarantined == True)) or 0

    # 4. Audit Chain Verification
    audit_verify = await verify_audit_chain(db)
    audit_total = audit_verify.get("total_events", 0)
    audit_ok = audit_verify.get("verified", True)

    # 5. Risk Distribution
    risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    findings_res = await db.execute(select(SecurityFinding.severity, func.count(SecurityFinding.id)).group_by(SecurityFinding.severity))
    for sev, cnt in findings_res.all():
        if sev and sev.value in risk_dist:
            risk_dist[sev.value] = cnt

    # 6. Evaluation Trends (Recent 7 days or batches)
    trends_stmt = select(TestExecution).order_by(TestExecution.id.asc()).limit(30)
    trends_res = await db.execute(trends_stmt)
    all_execs = trends_res.scalars().all()

    trend_buckets = defaultdict(lambda: {"passed": 0, "failed": 0, "total": 0})
    for ex in all_execs:
        date_key = ex.created_at.strftime("%b %d")
        trend_buckets[date_key]["total"] += 1
        if ex.status == EvaluationStatus.PASSED:
            trend_buckets[date_key]["passed"] += 1
        elif ex.status == EvaluationStatus.FAILED:
            trend_buckets[date_key]["failed"] += 1

    trends_list = [
        {"date": k, "passed": v["passed"], "failed": v["failed"], "total": v["total"]}
        for k, v in trend_buckets.items()
    ]
    if not trends_list:
        trends_list = [{"date": "Today", "passed": 0, "failed": 0, "total": 0}]

    # 7. Recent Security Events
    recent_events_stmt = select(AuditEvent).order_by(desc(AuditEvent.id)).limit(8)
    recent_events_res = await db.execute(recent_events_stmt)
    recent_events = recent_events_res.scalars().all()

    return DashboardMetricsResponse(
        total_evaluations=total_execs,
        passed_evaluations=passed_execs,
        failed_evaluations=failed_execs,
        inconclusive_evaluations=inconclusive_execs,
        prompt_injection_findings=prompt_inj_count,
        potential_leakage_events=leakage_count,
        cross_team_violations=cross_team_violations,
        files_scanned=files_scanned,
        files_quarantined=files_quarantined,
        audit_chain_verified=audit_ok,
        audit_total_events=audit_total,
        risk_distribution=risk_dist,
        evaluation_trends=trends_list,
        recent_events=[AuditEventResponse.model_validate(e) for e in recent_events]
    )
