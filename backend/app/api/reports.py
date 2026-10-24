from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import verify_audit_chain
from app.models.models import (
    User, TestExecution, SecurityFinding, LeakageTest, UploadedFile,
    EvaluationStatus, Severity
)

router = APIRouter(prefix="/reports", tags=["Reports and Export"])

@router.get("/summary")
async def get_executive_report(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generates an executive safety and vulnerability audit report."""
    total_tests = await db.scalar(select(func.count(TestExecution.id))) or 0
    passed_tests = await db.scalar(select(func.count(TestExecution.id)).where(TestExecution.status == EvaluationStatus.PASSED)) or 0
    failed_tests = await db.scalar(select(func.count(TestExecution.id)).where(TestExecution.status == EvaluationStatus.FAILED)) or 0
    inconclusive_tests = await db.scalar(select(func.count(TestExecution.id)).where(TestExecution.status == EvaluationStatus.INCONCLUSIVE)) or 0

    critical_findings = await db.scalar(select(func.count(SecurityFinding.id)).where(SecurityFinding.severity == Severity.CRITICAL)) or 0
    high_findings = await db.scalar(select(func.count(SecurityFinding.id)).where(SecurityFinding.severity == Severity.HIGH)) or 0
    medium_findings = await db.scalar(select(func.count(SecurityFinding.id)).where(SecurityFinding.severity == Severity.MEDIUM)) or 0

    total_leakage = await db.scalar(select(func.count(LeakageTest.id))) or 0
    total_files = await db.scalar(select(func.count(UploadedFile.id))) or 0
    quarantined_files = await db.scalar(select(func.count(UploadedFile.id)).where(UploadedFile.is_quarantined == True)) or 0

    audit_verify = await verify_audit_chain(db)

    pass_rate = round((passed_tests / total_tests * 100), 1) if total_tests > 0 else 100.0

    return {
        "report_id": f"REP-DEFENDX-{datetime.utcnow().strftime('%Y%m%d%H%M')}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generated_by": current_user.email,
        "executive_summary": (
            f"DefendX safety testing framework evaluated {total_tests} adversarial AI test cases with an "
            f"overall safety pass rate of {pass_rate}%. A total of {failed_tests} failure modes were detected, "
            f"resulting in {critical_findings} critical and {high_findings} high-severity security findings."
        ),
        "scope": {
            "platform": "DefendX Adversarial Safety Infrastructure",
            "evaluator_model": settings.LLM_MODEL_NAME,
            "provider_type": settings.LLM_PROVIDER,
            "hash_chain_verified": audit_verify.get("verified", True)
        },
        "metrics": {
            "total_evaluations": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "inconclusive": inconclusive_tests,
            "pass_rate_percentage": pass_rate
        },
        "findings_by_severity": {
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings
        },
        "leakage_testing": {
            "total_synthetic_canary_checks": total_leakage
        },
        "file_security": {
            "total_files_scanned": total_files,
            "quarantined_files": quarantined_files
        },
        "residual_risks_and_limitations": [
            "Keyword and heuristic input filtering reduces vulnerability surface but cannot guarantee total prevention of novel polyglot prompt injections.",
            "LLM nondeterminism may cause subtle variations in real-world deployment compared to isolated sandbox runs.",
            "SHA-256 hash chains detect log tampering within the database; for zero-trust guarantees, replicate audit chains to write-once cloud storage."
        ]
    }
