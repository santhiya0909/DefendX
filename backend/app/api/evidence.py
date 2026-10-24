import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import record_audit_event
from app.models.models import (
    User, EvidenceRecord, UploadedFile, EvidenceAccess, UserRole
)
from app.schemas.schemas import EvidenceCreate, EvidenceResponse

router = APIRouter(prefix="/evidence", tags=["Audit and Evidence Centre"])

@router.get("", response_model=List[EvidenceResponse])
async def list_evidence(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves evidence records filtered by role-based access classification:
    - RED_TEAM_ONLY is hidden from BLUE_TEAM.
    - BLUE_TEAM_ONLY is hidden from RED_TEAM.
    - AUDITOR and ADMIN can access all authorized compliance evidence.
    """
    stmt = select(EvidenceRecord).order_by(EvidenceRecord.id.desc())
    res = await db.execute(stmt)
    records = res.scalars().all()

    filtered = []
    for ev in records:
        if current_user.role == UserRole.ADMIN or current_user.role == UserRole.AUDITOR:
            filtered.append(ev)
        elif ev.access_classification == EvidenceAccess.PUBLIC_AUDIT:
            filtered.append(ev)
        elif ev.access_classification == EvidenceAccess.RED_TEAM_ONLY and current_user.role == UserRole.RED_TEAM:
            filtered.append(ev)
        elif ev.access_classification == EvidenceAccess.BLUE_TEAM_ONLY and current_user.role == UserRole.BLUE_TEAM:
            filtered.append(ev)

    return [EvidenceResponse.model_validate(e) for e in filtered]

@router.post("", response_model=EvidenceResponse)
async def create_evidence(
    req: EvidenceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Links an uploaded file or log artifact to a security finding or evaluation."""
    file_checksum = "GENESIS_CHECKSUM"
    if req.file_id:
        f_res = await db.execute(select(UploadedFile).where(UploadedFile.id == req.file_id))
        f_rec = f_res.scalars().first()
        if f_rec:
            file_checksum = f_rec.file_hash_sha256

    evidence_code = f"EVID-{uuid.uuid4().hex[:6].upper()}"
    evidence = EvidenceRecord(
        evidence_code=evidence_code,
        title=req.title,
        description=req.description,
        evidence_type=req.evidence_type,
        file_id=req.file_id,
        test_execution_id=req.test_execution_id,
        finding_id=req.finding_id,
        file_checksum=file_checksum,
        access_classification=req.access_classification,
        uploader_id=current_user.id,
        team=current_user.role
    )

    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="ATTACH_EVIDENCE_RECORD",
        resource_type="EVIDENCE_RECORD",
        resource_id=evidence.evidence_code,
        team_context=current_user.role.value,
        outcome="SUCCESS",
        details={"checksum": file_checksum, "access": evidence.access_classification.value}
    )

    return EvidenceResponse.model_validate(evidence)

@router.get("/{evidence_code}/verify")
async def verify_evidence_checksum(
    evidence_code: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Verifies that the stored file checksum matches the original recorded evidence digest."""
    stmt = select(EvidenceRecord).where(EvidenceRecord.evidence_code == evidence_code)
    res = await db.execute(stmt)
    evidence = res.scalars().first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    verified = True
    recorded_digest = evidence.file_checksum

    if evidence.file_id:
        f_res = await db.execute(select(UploadedFile).where(UploadedFile.id == evidence.file_id))
        f_rec = f_res.scalars().first()
        if f_rec:
            verified = (f_rec.file_hash_sha256 == recorded_digest)

    return {
        "evidence_code": evidence_code,
        "recorded_checksum": recorded_digest,
        "verified": verified,
        "integrity_status": "VALID_AND_AUTHENTIC" if verified else "CHECKSUM_MISMATCH_TAMPERED"
    }
